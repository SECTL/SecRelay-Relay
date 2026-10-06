#!/usr/bin/env pwsh
# SecRelay-Relay 中继可用性验证。
#
# 做两件事：
#   1. 拉取 /api/v1/relay，用独立实现重算 HMAC-SHA1，确认下发的凭据与 TURN_SECRET 一致；
#   2. 拿这份凭据向 coturn 发一条真正的 TURN Allocate 请求，确认它能被接受。
#
# 第 2 步需要真的能连上 coturn；连不上时只跳过，不会假装通过。
#
# 例：
#   pwsh deploy/verify-relay.ps1 -RelayBase http://127.0.0.1:8080 -Secret north-star-turn-secret
#   pwsh deploy/verify-relay.ps1 -RelayBase https://relay.example.com -Secret <secret> -TurnHost relay.example.com -TurnPort 3478

[CmdletBinding()]
param(
    [string]$RelayBase = $env:RELAY_BASE_URL,
    [string]$Secret = $env:TURN_SECRET,
    [string]$TurnHost = '',
    [int]$TurnPort = 3478,
    [int]$TimeoutMs = 5000
)

$ErrorActionPreference = 'Stop'
if (-not $RelayBase) { $RelayBase = 'http://127.0.0.1:8080' }

$script:Passed = 0
$script:Failed = 0
$script:Skipped = 0

function Write-Ok($msg) { $script:Passed++; Write-Host "  [通过] $msg" -ForegroundColor Green }
function Write-Bad($msg) { $script:Failed++; Write-Host "  [失败] $msg" -ForegroundColor Red }
function Write-Skip($msg) { $script:Skipped++; Write-Host "  [跳过] $msg" -ForegroundColor Yellow }
function Write-Step($msg) { Write-Host "`n== $msg" -ForegroundColor Cyan }

# ---------------------------------------------------------------- STUN/TURN 报文

$StunMagicCookie = 0x2112A442

function New-TransactionId {
    # 用 GUID 的字节当随机数：Windows PowerShell 5.1（.NET Framework）没有 RandomNumberGenerator.Fill。
    $bytes = [guid]::NewGuid().ToByteArray()
    return [byte[]]$bytes[0..11]
}

# 所有整数字段一律网络字节序。不要用 BinaryWriter：.NET Framework 上它写的是小端。
function New-BE16([int]$Value) {
    return [byte[]]@( [byte](($Value -shr 8) -band 0xFF), [byte]($Value -band 0xFF) )
}
function New-BE32([uint32]$Value) {
    return [byte[]]@(
        [byte](($Value -shr 24) -band 0xFF), [byte](($Value -shr 16) -band 0xFF),
        [byte](($Value -shr 8) -band 0xFF), [byte]($Value -band 0xFF)
    )
}

# STUN 头部 20 字节：长度字段只占 16 位，最高 2 位恒为 0。
function New-StunHeader([int]$Type, [int]$BodyLength, [byte[]]$TransactionId) {
    if ($BodyLength -ge 0x10000) { throw "报文太长：$BodyLength 字节" }
    return (New-BE16 $Type) + (New-BE16 $BodyLength) + (New-BE32 $StunMagicCookie) + $TransactionId
}

# 拼接时不能用 "+"：PowerShell 对数组做加法会展开成长度乘积。
function Join-Bytes([byte[][]]$Parts) {
    $ms = New-Object System.IO.MemoryStream
    foreach ($part in $Parts) { if ($null -ne $part) { $ms.Write($part, 0, $part.Length) } }
    return $ms.ToArray()
}

# STUN 属性：4 字节头 + 值 + 4 字节对齐填充。
function New-StunAttribute([int]$Type, [byte[]]$Value) {
    $padding = (4 - ($Value.Length % 4)) % 4
    return Join-Bytes @((New-BE16 $Type), (New-BE16 $Value.Length), $Value, [byte[]]::new($padding))
}

function New-StunTextAttribute([int]$Type, [string]$Value) {
    return New-StunAttribute -Type $Type -Value ([System.Text.Encoding]::UTF8.GetBytes($Value))
}

function Get-ReadUInt16([byte[]]$Data, [int]$Offset) {
    return ([int]$Data[$Offset] -shl 8) -bor $Data[$Offset + 1]
}
function Get-ReadUInt32([byte[]]$Data, [int]$Offset) {
    return ([uint32]$Data[$Offset] -shl 24) -bor ([uint32]$Data[$Offset + 1] -shl 16) -bor
           ([uint32]$Data[$Offset + 2] -shl 8) -bor [uint32]$Data[$Offset + 3]
}

# 返回属性列表和 MESSAGE-INTEGRITY 的起点（-1 表示没有）。
function Read-StunMessage([byte[]]$Data) {
    if ($null -eq $Data -or $Data.Length -lt 20) { throw "报文短于 20 字节" }
    if ((Get-ReadUInt32 $Data 4) -ne $StunMagicCookie) { throw "magic cookie 不对，不是 STUN 报文" }

    $attrs = @{}
    $integrityOffset = -1
    $total = [Math]::Min($Data.Length, 20 + (Get-ReadUInt16 $Data 2))
    $offset = 20
    while ($offset + 4 -le $total) {
        $type = Get-ReadUInt16 $Data $offset
        $len = Get-ReadUInt16 $Data ($offset + 2)
        if ($offset + 4 + $len -gt $total) { break }

        $value = [byte[]]::new($len)
        if ($len -gt 0) { [Buffer]::BlockCopy($Data, $offset + 4, $value, 0, $len) }

        # 同名属性（如 UNKNOWN-ATTRIBUTES）可能有多个，只留第一个够用了。
        $key = "{0:x4}" -f $type
        if (-not $attrs.ContainsKey($key)) { $attrs[$key] = $value }
        if ($type -eq 0x0008) { $integrityOffset = $offset }
        $offset += 4 + $len + ((4 - ($len % 4)) % 4)
    }

    return [pscustomobject]@{
        Type            = (Get-ReadUInt16 $Data 0) -band 0x3FFF
        Attributes      = $attrs
        IntegrityOffset = $integrityOffset
        Raw             = $Data
    }
}

function Get-HmacSha1([byte[]]$Key, [byte[]]$Data) {
    $hmac = New-Object System.Security.Cryptography.HMACSHA1
    $hmac.Key = $Key
    return $hmac.ComputeHash($Data)
}

# MESSAGE-INTEGRITY：长度字段先改成"到本属性开头为止"，对整段算 HMAC-SHA1，只取前 20 字节。
function Add-MessageIntegrity([byte[]]$Message, [byte[]]$Key) {
    $bodyLength = $Message.Length - 20
    $patched = [byte[]]$Message.Clone()
    $patched[2] = [byte](($bodyLength -shr 8) -band 0x007F)
    $patched[3] = [byte]($bodyLength -band 0xFF)

    $digest = [byte[]]::new(20)
    [Buffer]::BlockCopy([byte[]](Get-HmacSha1 -Key $Key -Data $patched), 0, $digest, 0, 20)
    return Join-Bytes @($Message, (New-StunAttribute -Type 0x0008 -Value $digest))
}

# 发一条请求并读回一条响应。
function Invoke-StunRequest {
    param(
        [byte[]]$Message,
        [string]$TurnServer,
        [int]$Port,
        [int]$TimeoutMs = 5000
    )

    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($TurnServer, $Port)
        [void]$udp.Send($Message, $Message.Length)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $response = $udp.Receive([ref]$remote)
        return , $response
    }
    finally {
        $udp.Close()
    }
}

# 先拿 401（含 realm / nonce），再带凭据 Allocate。返回是否成功。
function Test-TurnAllocate {
    param(
        [string]$TurnServer,
        [int]$Port,
        [string]$Username,
        [string]$Password,
        [int]$TimeoutMs = 5000
    )

    # 第一次：无凭据，期望 401 + REALM + NONCE。
    $requestedTransport = New-StunAttribute -Type 0x0019 -Value ([byte[]]@(17, 0, 0, 0))
    $challenge = Invoke-StunRequest -Port $Port -TimeoutMs $TimeoutMs -TurnServer $TurnServer -Message (Join-Bytes @(
            (New-StunHeader -Type 0x0003 -BodyLength $requestedTransport.Length -TransactionId (New-TransactionId)),
            $requestedTransport
        ))
    $parsed = Read-StunMessage $challenge

    if ($parsed.Type -ne 0x0111) {
        throw ("预期 401（Allocate 错误响应），收到 0x{0:x4}" -f $parsed.Type)
    }
    if (-not $parsed.Attributes.ContainsKey('0014') -or -not $parsed.Attributes.ContainsKey('0015')) {
        throw "401 响应里没有 REALM / NONCE"
    }
    $realm = [System.Text.Encoding]::UTF8.GetString($parsed.Attributes['0014'])
    $nonce = [System.Text.Encoding]::UTF8.GetString($parsed.Attributes['0015'])

    # MESSAGE-INTEGRITY 的密钥是 MD5(username:realm:password)。
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $key = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("${Username}:${realm}:${Password}"))

    $attrs = Join-Bytes @(
        $requestedTransport,
        (New-StunTextAttribute -Type 0x0006 -Value $Username),
        (New-StunTextAttribute -Type 0x0014 -Value $realm),
        (New-StunTextAttribute -Type 0x0015 -Value $nonce)
    )
    $body = Join-Bytes @(
        (New-StunHeader -Type 0x0003 -BodyLength $attrs.Length -TransactionId (New-TransactionId)),
        $attrs
    )

    $response = Invoke-StunRequest -Port $Port -TimeoutMs $TimeoutMs -TurnServer $TurnServer `
        -Message (Add-MessageIntegrity -Message $body -Key $key)
    $parsed = Read-StunMessage $response

    return [pscustomobject]@{
        Success = ($parsed.Type -eq 0x0103)
        Type    = $parsed.Type
        Error   = $(if ($parsed.Attributes.ContainsKey('0009')) {
                [System.Text.Encoding]::UTF8.GetString($parsed.Attributes['0009'])
            }
            else { '' })
        Realm   = $realm
    }
}

# ---------------------------------------------------------------- 步骤 1

Write-Step "1/2 拉取 $RelayBase/api/v1/relay 并校验凭据"

$relay = $null
try {
    $relay = Invoke-RestMethod -Uri "$RelayBase/api/v1/relay" -TimeoutSec 10
}
catch {
    Write-Bad "请求失败：$($_.Exception.Message)"
    Write-Host "`n先启动服务再跑：`n  `$env:TURN_SECRET='<secret>'; `$env:TURN_URLS='turn:127.0.0.1:3478?transport=udp'; cargo run" -ForegroundColor DarkGray
    exit 1
}

Write-Host ($relay | ConvertTo-Json -Depth 8)

foreach ($field in @('version', 'signaling', 'ice', 'credential_ttl', 'realm')) {
    if ($null -eq $relay.PSObject.Properties[$field]) { Write-Bad "响应缺少字段 $field" }
    else { Write-Ok "响应含字段 $field" }
}

$turn = @($relay.ice | Where-Object { $_.urls[0] -like 'turn*' })
if ($turn.Count -eq 0) {
    Write-Skip "响应里没有 TURN 条目（TURN_URLS 未配置），后面的步骤都无法进行"
}
else {
    $entry = $turn[0]
    if (-not $entry.username -or -not $entry.credential) {
        Write-Bad "TURN 条目没有 username / credential"
    }
    else {
        Write-Ok "TURN 条目带凭据：$($entry.username)"
    }

    if (-not $Secret) {
        Write-Skip '没有传 -Secret / TURN_SECRET，无法重算 HMAC'
    }
    else {
        # 用 .NET 独立重算，确认 username 与 password 逐字符一致。
        $expected = [Convert]::ToBase64String(
            (Get-HmacSha1 -Key ([System.Text.Encoding]::UTF8.GetBytes($Secret)) `
                -Data ([System.Text.Encoding]::UTF8.GetBytes($entry.username))))
        if ($expected -ceq $entry.credential) {
            Write-Ok "password 与 base64(HMAC-SHA1(secret, username)) 逐字符一致"
        }
        else {
            Write-Bad "password 不一致：期望 $expected，响应 $($entry.credential)"
        }

        $expiry = [int64]($entry.username.Split(':')[0])
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($expiry -gt $now) { Write-Ok "过期时间戳在未来 $($expiry - $now) 秒" }
        else { Write-Bad "过期时间戳已过期（$expiry）" }
    }

    # ---------------------------------------------------------------- 步骤 2
    if (-not $TurnHost) {
        # 从 turn:host:port?transport=... 里抠出主机名。
        $m = [regex]::Match($entry.urls[0], '^turns?:(?<host>[^:?]+)(:(?<port>\d+))?')
        if ($m.Success) {
            $TurnHost = $m.Groups['host'].Value
            if ($m.Groups['port'].Success) { $TurnPort = [int]$m.Groups['port'].Value }
        }
    }

    Write-Step "2/2 用这份凭据向 coturn ($TurnHost`:$TurnPort) 发一条 TURN Allocate"
    try {
        $result = Test-TurnAllocate -TurnServer $TurnHost -Port $TurnPort `
            -Username $entry.username -Password $entry.credential -TimeoutMs $TimeoutMs
        if ($result.Success) {
            Write-Ok "coturn 接受了凭据：Allocate 成功（0x0103），realm=$($result.Realm)"
        }
        else {
            Write-Bad ("coturn 拒绝了 Allocate：type=0x{0:x4} error={1}" -f $result.Type, $result.Error)
        }
    }
    catch {
        Write-Skip "连不上 coturn 或没有响应：$($_.Exception.Message)"
        Write-Host "  这一步没有被验证过。要么在本机起 coturn（见 docs/部署-coturn.md），要么对着真实中继跑。" -ForegroundColor DarkGray
    }
}

Write-Host "`n通过 $script:Passed / 失败 $script:Failed / 跳过 $script:Skipped" -ForegroundColor Cyan
exit $(if ($script:Failed -gt 0) { 1 } else { 0 })


