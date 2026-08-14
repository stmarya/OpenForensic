@{
    Severity     = @('Error', 'Warning')

    # Write-Host disengaja: seluruh UI adalah TUI berwarna di console.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSUseSingularNouns'
    )

    Rules        = @{
        PSAvoidUsingCmdletAliases      = @{ Enable = $true }
        PSUseConsistentIndentation     = @{ Enable = $true; IndentationSize = 4; Kind = 'space' }
        PSPlaceOpenBrace               = @{ Enable = $true; OnSameLine = $true }
        PSAvoidUsingPlainTextForPassword = @{ Enable = $true }
        PSAvoidUsingConvertToSecureStringWithPlainText = @{ Enable = $true }
    }
}
