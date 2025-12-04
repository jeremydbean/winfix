$Password = "smoke007"
$Salt = [System.Text.Encoding]::UTF8.GetBytes("WinFixSalt123")
$Rfc = New-Object System.Security.Cryptography.Rfc2898DeriveBytes $Password, $Salt, 1000

$Aes = New-Object System.Security.Cryptography.AesManaged
$Aes.Key = $Rfc.GetBytes(32)

function Encrypt-String($ClearText) {
    $Aes.GenerateIV()
    $IV = $Aes.IV
    $Encryptor = $Aes.CreateEncryptor()
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($ClearText)
    $EncryptedBytes = $Encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)
    return [Convert]::ToBase64String($IV + $EncryptedBytes)
}

$ClientId = "CeOCK_8II5N0gU2M49QayDqHIVc"
$ClientSecret = "rAuGUTxQCLaglsxSOQa991au_uW2K_8lpW1ba7wMP5twIHaIRM5bAA"

Write-Host "CID:$(Encrypt-String $ClientId)"
Write-Host "SEC:$(Encrypt-String $ClientSecret)"
