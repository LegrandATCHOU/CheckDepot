<#
.SYNOPSIS
    CheckDépôt : diagnostic de sécurité d'un PC Windows déposé chez un réparateur.

.DESCRIPTION
    Lit l'état de sécurité du poste (lecture seule, aucune modification),
    calcule un score sur 100 et produit :
      - un rapport HTML d'une page, en français simple, à remettre au client
        (imprimable en PDF depuis le navigateur) ;
      - un fichier JSON pour l'historique du réparateur.

.PARAMETER Client
    Nom du client (apparaît sur le rapport).

.PARAMETER Ticket
    Numéro de la fiche de dépôt.

.PARAMETER Sortie
    Dossier où écrire les rapports (par défaut : .\rapports).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\CheckDepot.ps1 -Client "Mme Durand" -Ticket "LF-2026-0142"

.NOTES
    Lancer en administrateur pour les contrôles BitLocker, TPM, Secure Boot et SMBv1.
    Compatible Windows PowerShell 5.1 et PowerShell 7. Enregistrer ce fichier en UTF-8 avec BOM.
#>
[CmdletBinding()]
param(
    [string]$Client = "Client",
    [string]$Ticket = (Get-Date -Format "yyyyMMdd-HHmm"),
    [string]$Sortie = ""
)

$ErrorActionPreference = "Stop"
# Dossier du script (en Windows PowerShell 5.1, $PSScriptRoot est vide dans le bloc param).
$racine = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $Sortie) { $Sortie = Join-Path $racine "rapports" }
$config = Get-Content (Join-Path $racine "config.json") -Raw -Encoding UTF8 | ConvertFrom-Json
$estAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$resultats = New-Object System.Collections.Generic.List[object]

function Ajouter-Controle {
    param(
        [string]$Id,          # identifiant court, relié aux prestations de config.json
        [string]$Titre,       # ce qu'on vérifie, en mots simples
        [ValidateSet("ok", "attention", "critique", "inconnu")]
        [string]$Etat,
        [string]$Constat,     # ce qu'on a trouvé
        [string]$Risque = "", # pourquoi c'est un problème, pour le client
        [int]$Poids = 10      # importance dans le score
    )
    $resultats.Add([pscustomobject]@{
        Id = $Id; Titre = $Titre; Etat = $Etat; Constat = $Constat; Risque = $Risque; Poids = $Poids
    })
}

# Exécute un contrôle sans que l'échec d'un seul bloque tout le diagnostic.
function Tester {
    param([string]$Id, [string]$Titre, [int]$Poids, [scriptblock]$Bloc)
    try { & $Bloc }
    catch {
        Ajouter-Controle -Id $Id -Titre $Titre -Etat "inconnu" -Poids $Poids `
            -Constat "Contrôle impossible : $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------- Contrôles

$os = Get-CimInstance Win32_OperatingSystem
$build = [int]$os.BuildNumber

Tester "systeme" "Version de Windows encore suivie" 15 {
    # Windows 10 = builds < 22000 ; support grand public terminé le 14/10/2025.
    if ($build -lt 22000) {
        Ajouter-Controle "systeme" "Version de Windows encore suivie" "critique" `
            "$($os.Caption) (build $build) : Windows 10 ne reçoit plus de correctifs de sécurité gratuits." `
            "Les nouvelles failles ne seront plus corrigées." 15
    } else {
        Ajouter-Controle "systeme" "Version de Windows encore suivie" "ok" "$($os.Caption) (build $build)." "" 15
    }
}

Tester "maj" "Mises à jour récentes" 15 {
    $derniere = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if (-not $derniere) {
        Ajouter-Controle "maj" "Mises à jour récentes" "inconnu" "Aucune date de mise à jour trouvée." "" 15
    } else {
        $jours = [int]((Get-Date) - $derniere.InstalledOn).TotalDays
        $etat = if ($jours -le 35) { "ok" } elseif ($jours -le 90) { "attention" } else { "critique" }
        Ajouter-Controle "maj" "Mises à jour récentes" $etat `
            "Dernière mise à jour installée il y a $jours jours ($($derniere.HotFixID))." `
            "Un PC pas à jour est la porte d'entrée la plus fréquente des virus." 15
    }
}

Tester "antivirus" "Antivirus actif et à jour" 15 {
    $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
    $noms = ($av | ForEach-Object { $_.displayName }) -join ", "
    $mp = $null
    try { $mp = Get-MpComputerStatus } catch { }
    if ($mp -and $mp.AntivirusEnabled) {
        $age = $mp.AntivirusSignatureAge
        $etat = if ($mp.RealTimeProtectionEnabled -and $age -le 7) { "ok" } else { "attention" }
        Ajouter-Controle "antivirus" "Antivirus actif et à jour" $etat `
            "Microsoft Defender actif, protection en temps réel : $($mp.RealTimeProtectionEnabled), signatures de $age jour(s)." `
            "Sans protection en temps réel, un fichier piégé peut s'exécuter sans alerte." 15
    } elseif ($av) {
        Ajouter-Controle "antivirus" "Antivirus actif et à jour" "ok" "Antivirus déclaré : $noms (état détaillé non lisible)." "" 15
    } else {
        Ajouter-Controle "antivirus" "Antivirus actif et à jour" "critique" "Aucun antivirus détecté." `
            "Le PC n'est protégé contre aucun logiciel malveillant." 15
    }
}

Tester "parefeu" "Pare-feu Windows" 10 {
    $off = Get-NetFirewallProfile | Where-Object { -not $_.Enabled }
    if ($off) {
        Ajouter-Controle "parefeu" "Pare-feu Windows" "critique" `
            "Pare-feu désactivé sur : $(($off.Name) -join ', ')." `
            "Le PC accepte des connexions qu'il devrait bloquer, surtout sur un Wi-Fi public." 10
    } else {
        Ajouter-Controle "parefeu" "Pare-feu Windows" "ok" "Pare-feu actif sur tous les profils." "" 10
    }
}

Tester "chiffrement" "Chiffrement du disque (BitLocker)" 10 {
    if (-not $estAdmin) { throw "lancer le script en administrateur" }
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
    if ($bl.ProtectionStatus -eq "On") {
        Ajouter-Controle "chiffrement" "Chiffrement du disque (BitLocker)" "ok" "Disque système chiffré." "" 10
    } else {
        Ajouter-Controle "chiffrement" "Chiffrement du disque (BitLocker)" "attention" "Disque système non chiffré." `
            "En cas de vol ou de perte, toutes les données sont lisibles." 10
    }
}

Tester "admins" "Comptes administrateurs" 10 {
    # S-1-5-32-544 = groupe Administrateurs, quelle que soit la langue de Windows.
    $membres = Get-LocalGroupMember -SID "S-1-5-32-544"
    # On ne compte que les comptes actifs (le compte « Administrateur » intégré est souvent désactivé).
    $actifs = foreach ($m in $membres) {
        if ($m.PrincipalSource -eq "Local") {
            $u = Get-LocalUser -SID $m.SID
            if ($u.Enabled) { $m }
        } else { $m }
    }
    $nb = @($actifs).Count
    # Le compte de la personne connectée fait-il partie des administrateurs ?
    $utilisateurAdmin = [bool]($membres | Where-Object { $_.Name -like "*\$env:USERNAME" })
    $etat = if ($nb -gt 2 -or $utilisateurAdmin) { "attention" } else { "ok" }
    Ajouter-Controle "admins" "Comptes administrateurs" $etat `
        "$nb compte(s) administrateur(s). Compte utilisé au quotidien administrateur : $utilisateurAdmin." `
        "Travailler en administrateur permet à un virus de prendre le contrôle complet du PC." 10
}

Tester "invite" "Compte Invité" 5 {
    # Seul le compte Invité est vérifié : la propriété PasswordRequired de Get-LocalUser
    # ne dit pas si un mot de passe existe (faux positifs sur les comptes Microsoft).
    $invite = Get-LocalUser | Where-Object { $_.SID -like "*-501" -and $_.Enabled }
    if ($invite) {
        Ajouter-Controle "invite" "Compte Invité" "critique" `
            "Le compte Invité est activé." "N'importe qui peut ouvrir une session sur le PC." 5
    } else {
        Ajouter-Controle "invite" "Compte Invité" "ok" "Compte Invité désactivé." "" 5
    }
}

Tester "bureau_distance" "Bureau à distance" 5 {
    $deny = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections
    if ($deny -eq 0) {
        Ajouter-Controle "bureau_distance" "Bureau à distance" "attention" "Le bureau à distance est activé." `
            "S'il n'est pas utilisé, c'est une porte ouverte inutile pour les attaquants." 5
    } else {
        Ajouter-Controle "bureau_distance" "Bureau à distance" "ok" "Bureau à distance désactivé." "" 5
    }
}

Tester "uac" "Contrôle de compte d'utilisateur (UAC)" 5 {
    $lua = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
    $etat = if ($lua -eq 1) { "ok" } else { "critique" }
    Ajouter-Controle "uac" "Contrôle de compte d'utilisateur (UAC)" $etat "UAC activé : $($lua -eq 1)." `
        "Sans UAC, un programme peut modifier le système sans rien demander." 5
}

Tester "smb1" "Ancien protocole de partage SMBv1" 5 {
    if (-not $estAdmin) { throw "lancer le script en administrateur" }
    $smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
    $etat = if ($smb1) { "critique" } else { "ok" }
    Ajouter-Controle "smb1" "Ancien protocole de partage SMBv1" $etat "SMBv1 activé : $smb1." `
        "Protocole utilisé par le rançongiciel WannaCry en 2017." 5
}

Tester "demarrage" "Démarrage sécurisé (Secure Boot et TPM)" 5 {
    if (-not $estAdmin) { throw "lancer le script en administrateur" }
    $sb = $false; try { $sb = Confirm-SecureBootUEFI } catch { }
    $tpm = (Get-Tpm).TpmPresent
    $etat = if ($sb -and $tpm) { "ok" } else { "attention" }
    Ajouter-Controle "demarrage" "Démarrage sécurisé (Secure Boot et TPM)" $etat "Secure Boot : $sb ; puce TPM : $tpm." `
        "Protège contre les logiciels malveillants qui se lancent avant Windows." 5
}

Tester "disque" "Espace disque libre" 5 {
    $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    $pct = [math]::Round($d.FreeSpace / $d.Size * 100)
    $etat = if ($pct -ge 15) { "ok" } elseif ($pct -ge 8) { "attention" } else { "critique" }
    Ajouter-Controle "disque" "Espace disque libre" $etat "$pct % libre sur $env:SystemDrive." `
        "Un disque plein empêche les mises à jour de s'installer." 5
}

# La sauvegarde ne se vérifie pas de façon fiable par script : question posée au client.
Ajouter-Controle "sauvegarde" "Sauvegarde des données" "inconnu" `
    "À demander au client : avez-vous une copie de vos fichiers ailleurs que sur ce PC ?" `
    "Une panne, un vol ou un rançongiciel = perte définitive des photos et documents." 0

# ---------------------------------------------------------------- Score

$evalues = $resultats | Where-Object { $_.Etat -ne "inconnu" -and $_.Poids -gt 0 }
$total = ($evalues | Measure-Object Poids -Sum).Sum
$points = 0
foreach ($r in $evalues) {
    switch ($r.Etat) { "ok" { $points += $r.Poids } "attention" { $points += $r.Poids / 2 } }
}
$score = if ($total) { [int][math]::Round($points / $total * 100) } else { 0 }
$niveau = if ($score -ge 80) { "vert" } elseif ($score -ge 50) { "orange" } else { "rouge" }
# Un seul point critique suffit à empêcher le vert.
if ($niveau -eq "vert" -and ($resultats | Where-Object { $_.Etat -eq "critique" })) { $niveau = "orange" }

# Trois actions prioritaires : d'abord les critiques, puis par poids.
$ordre = @{ "critique" = 0; "attention" = 1 }
$priorites = $resultats | Where-Object { $_.Etat -in "critique", "attention" } |
    Sort-Object @{ e = { $ordre[$_.Etat] } }, @{ e = { $_.Poids }; Descending = $true } |
    Select-Object -First 3

# ---------------------------------------------------------------- Sorties

New-Item -ItemType Directory -Force -Path $Sortie | Out-Null
$horodatage = Get-Date -Format "yyyy-MM-dd_HHmm"
$base = Join-Path $Sortie ("{0}_{1}" -f ($Ticket -replace '[^\w\-]', '_'), $horodatage)

$donnees = [pscustomobject]@{
    outil = "CheckDépôt"; version = "0.1.1"
    date = (Get-Date).ToString("s"); client = $Client; ticket = $Ticket
    poste = $env:COMPUTERNAME; systeme = $os.Caption; build = $build
    administrateur = $estAdmin; score = $score; niveau = $niveau
    controles = $resultats
}
$donnees | ConvertTo-Json -Depth 5 | Set-Content "$base.json" -Encoding UTF8

function Html([string]$t) { [System.Net.WebUtility]::HtmlEncode($t) }

$couleurs = @{ vert = "#1E8E3E"; orange = "#E37400"; rouge = "#C5221F" }
$pastilles = @{ ok = "&#9989;"; attention = "&#9888;&#65039;"; critique = "&#10060;"; inconnu = "&#10067;" }

$lignes = foreach ($r in $resultats) {
    "<tr><td>$($pastilles[$r.Etat])</td><td><b>$(Html $r.Titre)</b><br><span class='c'>$(Html $r.Constat)</span></td></tr>"
}
$actions = foreach ($p in $priorites) {
    $presta = $config.prestations.($p.Id)
    $offre = if ($presta) { "<br><span class='o'>Proposé par $(Html $config.atelier.nom) : $(Html $presta.libelle) ($(Html $presta.tarif))</span>" } else { "" }
    "<li><b>$(Html $p.Titre)</b> : $(Html $p.Risque)$offre</li>"
}
if (-not $actions) { $actions = "<li>Aucune action urgente. Pensez quand même à vérifier vos sauvegardes.</li>" }

$html = @"
<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>CheckDépôt $(Html $Ticket)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;max-width:780px;margin:24px auto;color:#202124;font-size:13px}
h1{font-size:20px;margin:0}.sous{color:#5f6368}
.score{display:flex;align-items:center;gap:16px;margin:16px 0;padding:14px;border-radius:10px;background:#f1f3f4}
.rond{width:84px;height:84px;border-radius:50%;background:$($couleurs[$niveau]);color:#fff;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:700}
table{width:100%;border-collapse:collapse}td{padding:6px;border-bottom:1px solid #e8eaed;vertical-align:top}
.c{color:#5f6368}.o{color:#1a73e8}h2{font-size:15px;margin:18px 0 6px}
.pied{margin-top:18px;color:#5f6368;font-size:11px}@media print{body{margin:0}}
</style></head><body>
<h1>Bilan sécurité de votre ordinateur</h1>
<div class="sous">$(Html $config.atelier.nom) · Fiche $(Html $Ticket) · $(Html $Client) · $(Get-Date -Format "dd/MM/yyyy") · Poste $(Html $env:COMPUTERNAME)</div>
<div class="score"><div class="rond">$score</div><div><b>Note de sécurité : $score / 100 ($niveau)</b><br>
Ce bilan vérifie les protections de base de votre PC. Il ne remplace pas un audit complet.</div></div>
<h2>Les 3 actions à faire en priorité</h2><ol>$($actions -join "")</ol>
<h2>Détail des contrôles</h2><table>$($lignes -join "")</table>
<div class="pied">Contrôles en lecture seule : aucune modification n'a été faite sur votre ordinateur.
$(if (-not $estAdmin) { "Certains contrôles n'ont pas pu être faits (droits administrateur manquants)." })
<br>$(Html $config.atelier.contact) · Généré par CheckDépôt 0.1.1</div>
</body></html>
"@
$html | Set-Content "$base.html" -Encoding UTF8

Write-Host ""
Write-Host "Score : $score / 100 ($niveau)"
Write-Host "Rapport client : $base.html  (ouvrir puis Ctrl+P > Enregistrer en PDF)"
Write-Host "Historique     : $base.json"
if (-not $estAdmin) { Write-Warning "Relancer en administrateur pour BitLocker, SMBv1, Secure Boot et TPM." }
