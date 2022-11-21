add-type -Path '.\System.Formats.Cbor.7.0.0\lib\net6.0\System.Formats.Cbor.dll'

function ConvertFrom-TLV {
    param (
        [byte[]] $bytes
    )
    
    while ($bytes.Length -gt 4){
        $t = $bytes[0..1]
        $l = [bitconverter]::ToUInt16($bytes[3..2],0)
        if ($bytes.Length -lt ($l+3)) {
            #throw "Attempt to read past end of array, check data."
            Write-Host "nope"
        }
        $v = $bytes[4..($l+3)]
        $bytes = $bytes[($l+4)..($bytes.Length-1)]
        [PSCustomObject]@{
            Tag = $t
            Length = $l
            Value = $v
        }
    }
}

function ConvertTo-TLV {
    param (
        [byte[]]$Tag = [byte[]](0,0),
        [byte[]]$Value
    )

    if ($Tag.Length -ne 2) {throw "Tag must be two bytes"}
    $l = [System.BitConverter]::GetBytes([uint16]$Value.Length)
    if ([System.BitConverter]::IsLittleEndian) {[Array]::Reverse($l)}
    $tag+$l+$value
     
    
}
function ConvertFrom-SSHAttestation {
    [CmdletBinding()]
    param (
        [Parameter()]
        $Path
    )

    <#
    ssh attestation file format: https://fossies.org/linux/openssh/PROTOCOL.u2f
    TLV Format
    Fields
    0x0000 - attestation version, ascii "ssh-sk-attest-v01"
    0x0000 - attestation certificate, binary
    0x0000 - enrollment signature, binary
    0x0000 - authenticator data, CBOR
    ????
    #>
    
    $bytes = Get-Content $Path -AsByteStream

    $Attestation = ConvertFrom-TLV $bytes

    [PSCustomObject]@{
        Version = [System.Text.Encoding]::UTF8.GetString($Attestation[0].value) 
        Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[byte[]]($Attestation[1].value))
        Signature = $Attestation[2].value
        AuthenticatorData = ConvertFrom-CBORByteString -Bytes $Attestation[3].value 
        #UnpackedAuthenticatorData = 
    }
}

function ConvertFrom-CBORByteString {
    [CmdletBinding()]
    param (
        # Parameter help description
        [byte[]]
        $Bytes
    )
    $Reader = New-Object -TypeName System.Formats.Cbor.Cborreader -ArgumentList $bytes, 'strict', $false
    if ($Reader.PeekState().ToString() -ne 'ByteString') {
        throw "Next CBOR Data is not Byte String"
    } 
    $Reader.ReadByteString() 
}

function ConvertFrom-CBORCOSEKey {
    param (
        [byte[]] $Bytes
    )

    $KTY = 1
    $OKP = 1
    $EC2 = 2

    $ALG = 3
    $ES256 = -7
    $EDDSA = -8 
    $PS256 = -37
    
    $Reader = New-Object -TypeName System.Formats.Cbor.Cborreader -ArgumentList $bytes, 'strict', $false
    if ($Reader.PeekState().ToString() -ne 'StartMap') {
        throw "Next CBOR Data is not a Map Start"
    } 
    $MapLength = $Reader.ReadStartMap() 
    #Write-Host "Map Length $MapLength"
    $RawMap = @{}
    $Map = @{}
    foreach ($record in (1..$MapLength)) {
        #$Reader.PeekState()
        $key = $reader.ReadInt32()
        #$Reader.PeekState()
        $value = switch ($Reader.PeekState().ToString()) {
            'UnsignedInteger' { $Reader.ReadInt32() }
            'NegativeInteger' { $Reader.ReadInt32() }
            'ByteString'      { $Reader.ReadByteString()}
        }
        $RawMap[$Key] = $value
    }
    $RawMap

    #KTY
    switch ($RawMap[$KTY]) {
        $OKP {
            # OKP Octet Key Pair
            $Map['KTY'] = 'OKP'
            If ($MapLength -ne 4) {
                Throw "CBOR Encoded Map length does not match KTY(1) of OKP(1)"
            }
          }
        $EC2 {
            # EC2 Elliptic Curve Keys w/ x- and y-coordinate pair
            $Map['KTY'] = 'EC2'
            If ($MapLength -ne 5) {
                Throw "CBOR Encoded Map length does not match KTY(1) of EC2(2)"
            }
        }
        Default {
            Throw "Unsupported KTY of $($RawMap[1])"
        }
    }



}

function Test-SSHAttestationSignature {
    param (
        $AttestationFilePath, 
        $ChallengeFilePath
    )

    $Attestation = ConvertFrom-SSHAttestation $AttestationFilePath
    $clientdatahash = [System.Convert]::FromHexString((Get-FileHash -Algorithm SHA256 -Path $ChallengeFilePath).hash) 

    $Data = $Attestation.AuthenticatorData + $ClientDataHash
    $Attestation.Certificate.PublicKey.GetECDsaPublicKey().VerifyData($data, $Attestation.Signature, 'SHA256', 'Rfc3279DerSequence')
}

function Test-SSHAttestationCertificate {
    param (
        $AttestationFilePath,
        $RootCertificatePath
    )
    $Attestation = ConvertFrom-SSHAttestation $AttestationFilePath

    $Root = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $RootCertificatePath
    $CertChain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain -ArgumentList $false
    $CertChain.ChainPolicy.TrustMode = 'CustomRootTrust'
    $CertChain.ChainPolicy.RevocationMode = 'NoCheck'
    $CertChain.ChainPolicy.CustomTrustStore.Add($Root) | Out-Null
    $certChain.Build($Attestation.Certificate) 
    
}

function Get-FIDO2Flags {
    param (
        [byte]$Flags
    )

    if ($Flags -band 0x01) {'User Presence (UP)'}
    if ($Flags -band 0x04) {'User Verification (UV)'}
    if ($Flags -band 0x40) {'Attestation (AT)'}
    if ($Flags -band 0x80) {'Extensions (ED)'}
    <#
    
    [PSCustomObject]@{
        'User Presence (UP)' = [bool]($Flags -band 0x01)
        'User Verification (UV)' = [bool]($Flags -band 0x04)
        'Attestation (AT)' = [bool]($Flags -band 0x40)
        'Extensions (ED)' = [bool]($Flags -band 0x80)
    }
    #>
}

function ConvertTo-BigEndian {
    param (
        [byte[]] $Bytes
    )

    if ([system.bitconverter]::IsLittleEndian) {
        [array]::Reverse($Bytes)
    }
    $Bytes
}

function ConvertFrom-FIDO2AuthenticatorData {
    param (
        [byte[]]$Bytes
    )

    $Offset = 0; 

    #RPID Hash, required, 32 Bytes
    $Length = 32
    $RPIDHash = $Bytes[($Offset)..($Length-1)]
    $Offset += $Length;

    #Flags, required, 1 Byte
    $Flags = Get-FIDO2Flags $Bytes[$Offset]
    $Offset += 1

    #SignCount, required, 4 Bytes Unsigned 32-bit integer, big-endian
    #Not sure about bit order here?
    $Length = 4
    #Write-Host $Offset, $Length
    
    #$Bytes[($Offset)..($Offset+$Length)] | Format-Hex
    #ConvertTo-BigEndian -Bytes $Bytes[($Offset)..($Offset+$Length-1)] | Format-Hex
    $Signcount = [bitconverter]::ToUInt32((ConvertTo-BigEndian -Bytes $Bytes[($Offset)..($Offset+$Length-1)]),0)
    $Offset += $Length 

    
    #AttestedCredentialData, optional, variable length
    if (($flags -contains 'Attestation (AT)')){
        if ($Offset -gt $Bytes.Length) {
            Throw "Attestation Data Specified, but no more bytes left in CredentialData."
        }

        #AAGUID, required, 16 bytes
        $Length = 16
        $AAGUID = $Bytes[($Offset)..($Offset+$Length-1)]
        $Offset += $Length

        #Credential ID Length, required, 2 bytes unsinged 16-bit big-endian integer
        $Length = 2
        $CredentialIDLength = [bitconverter]::ToUInt16((ConvertTo-BigEndian -Bytes $Bytes[($Offset)..($Offset+$Length-1)]),0)
        $Offset += $Length

        #Credential ID, required, Length is $CredentialIDLength
        $Length = $CredentialIDLength
        $CredentialID = $Bytes[($Offset)..($Offset+$Length-1)]
        $Offset += $Length

        #Public Key in COSE_Key Format
        $Remainder = $Bytes[$Offset..($Bytes.Length-1)]
        #$Remainder | Format-Hex
        #[System.Convert]::ToHexString($Remainder)

    }


    #AAGUID, 16 Bytes

    

    #Extensions

    [PSCustomObject]@{
        RPIDHash = [System.Convert]::ToHexString($RPIDHash)
        Flags = $Flags
        SignatureCounter = $Signcount
        AAGUID = [System.Convert]::ToHexString($AAGUID)
        #CredentialIDLength = $CredentialIDLength
        CredentialID = [System.Convert]::ToHexString($CredentialID)
        PublicKeyRaw = $Remainder


    }
    
}

$Attestation = ConvertFrom-SSHAttestation .\attestation.bin
#$Attestation | Format-List 
#ConvertFrom-CBOR $Attestation.AuthenticatorData | Format-Hex

#Working Test that Authenticator Data & Challenge was signed by Attestation Certificate
Test-SSHAttestationSignature -AttestationFilePath .\attestation.bin -ChallengeFilePath .\challengefile

#Working Test that Attestation Certificate was signed by Yubico Root 
if (-not (Test-Path .\yubico-u2f-ca-certs.txt)) {
    Invoke-WebRequest 'https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt' -OutFile yubico-u2f-ca-certs.txt | Out-Null
}
Test-SSHAttestationCertificate -AttestationFilePath .\attestation.bin -RootCertificatePath .\yubico-u2f-ca-certs.txt


#$Attestation.AuthenticatorData | Format-Hex
#ConvertFrom-FIDO2AuthenticatorData $Attestation.AuthenticatorData
$AuthenticatorData = ConvertFrom-FIDO2AuthenticatorData $Attestation.AuthenticatorData
$AuthenticatorData | Format-List

#Reconstruct Public Key from Authenticator Data
$PubKeyInfo = ConvertFrom-CBORCOSEKey $AuthenticatorData.PublicKeyRaw 
$keytype= 'sk-ssh-ed25519@openssh.com'
$pubkey =ConvertTo-TLV -Value (([system.Text.Encoding]::UTF8).GetBytes($keytype)) #|format-hex
$pubkey+=ConvertTo-TLV -Value $PubKeyInfo[-2] #| Format-Hex
$pubkey+=ConvertTo-TLV -Value (([system.Text.Encoding]::UTF8).GetBytes('ssh:')) #|format-hex
$pubkey = [System.Convert]::ToBase64String($pubkey)
"$keytype $pubkey" | Set-Content sk.pub
"$keytype $pubkey"
return