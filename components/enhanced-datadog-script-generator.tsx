
'use client'

import { useState, useRef } from 'react'
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { Checkbox } from "@/components/ui/checkbox"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Copy, ExternalLink } from 'lucide-react'

export function EnhancedDatadogScriptGeneratorComponent() {
  const [step, setStep] = useState(1)
  const [formData, setFormData] = useState({
    os: '',
    site: '',
    apiKey: '',
    env: 'test',
    features: {
      logs: true,
      apm: true,
      processAgent: true,
      networkMonitoring: true,
      cloudSecurityPostureManagement: true,
      cloudWorkloadSecurity: true,
      sbom: true,
      otlp: false,
      universalServiceMonitoring: true,
      threatProtection: true,
      softwareCompositionAnalysis: true,
      codeSecurityProfiling: true,
      containerHostVulnerabilityManagement: true,
    },
    apmInstrumentationLanguages: {
      java: false,
      js: false,
      python: false,
      dotnet: false,
      ruby: false,
      php: false,
    },
    advancedOptions: {
      collectAllLogs: true,
      updateLogPermissions: true,
      collectIISLogs: true,
      collectWindowsEventLogs: true,
      collectAllWindowsLogs: true
    },
  })

  const [generatedScript, setGeneratedScript] = useState('')
  const scriptRef = useRef<HTMLTextAreaElement>(null)

  const getKubernetesUrl = () => {
    switch (formData.site) {
      case 'datadoghq.com':
        return 'https://app.datadoghq.com/account/settings/agent/latest?platform=kubernetes'
      case 'us3.datadoghq.com':
        return 'https://us3.datadoghq.com/account/settings/agent/latest?platform=kubernetes'
      case 'us5.datadoghq.com':
        return 'https://us5.datadoghq.com/account/settings/agent/latest?platform=kubernetes'
      case 'datadoghq.eu':
        return 'https://app.datadoghq.eu/account/settings/agent/latest?platform=kubernetes'
      case 'ap1.datadoghq.com':
        return 'https://ap1.datadoghq.com/account/settings/agent/latest?platform=kubernetes'
      default:
        return 'https://app.datadoghq.com/account/settings/agent/latest?platform=kubernetes'
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setFormData((prev) => ({ ...prev, [name]: value }))
  }

  const handleFeatureToggle = (feature: string) => {
    setFormData((prev) => ({
      ...prev,
      features: { ...prev.features, [feature]: !prev.features[feature as keyof typeof prev.features] },
    }))
  }

  const handleApmLanguageToggle = (language: string) => {
    setFormData((prev) => ({
      ...prev,
      apmInstrumentationLanguages: {
        ...prev.apmInstrumentationLanguages,
        [language]: !prev.apmInstrumentationLanguages[language as keyof typeof prev.apmInstrumentationLanguages],
      },
    }))
  }

  const handleAdvancedOptionToggle = (option: string) => {
    setFormData((prev) => ({
      ...prev,
      advancedOptions: { ...prev.advancedOptions, [option]: !prev.advancedOptions[option as keyof typeof prev.advancedOptions] },
    }))
  }

  const nextStep = () => {
    if (step === 1 && !formData.os) {
      alert("Please select a platform.")
      return
    }
    if (step === 2 && !formData.site) {
      alert("Please select a Datadog site.")
      return
    }

    // If Kubernetes is selected and we're moving past site selection
    if (formData.os === 'kubernetes' && step === 2) {
      window.open(getKubernetesUrl(), '_blank')
    }
    
    if (step === 3 && !formData.apiKey && formData.os !== 'kubernetes') {
      alert("Please enter your API key.")
      return
    }

    setStep(step + 1)
  }

  const prevStep = () => {
    setStep(step - 1)
  }

  const generateScript = () => {
    if (formData.os === 'linux') {
      const selectedApmLangs = Object.entries(formData.apmInstrumentationLanguages)
        .filter(([_, value]) => value)
        .map(([key]) => {
          switch (key) {
            case 'js': return 'js:5'
            case 'python': return 'python:3'
            case 'dotnet': return 'dotnet:3'
            case 'ruby': return 'ruby:2'
            case 'php': return 'php:1'
            default: return `${key}:1`
        }
      });
  const apmInstrumentationLibraries =
    formData.features.apm && selectedApmLangs.length
      ? `DD_APM_INSTRUMENTATION_LIBRARIES=${selectedApmLangs.join(',')} \\`
      : '';

      let script = `

#!/bin/bash

# This is an unofficial Datadog Agent Installation Script
# This is not affiliated with Datadog, please reach out to your Datadog account manager if you have any issues.

set -x

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Please run this script as root or with sudo."
   exit 1
fi

# Datadog site and API key
export DD_SITE="${formData.site}"
export DD_API_KEY="${formData.apiKey}"
export ENV_NAME="${formData.env}"

# Datadog Environment Variables
export DATADOG_ENV_FILE="/etc/profile.d/datadog_env.sh"

# Environment
export ENV_NAME="${formData.env}"
${formData.features.apm ? 'export DD_LOGS_INJECTION=true' : ''}
${formData.features.apm ? 'export DD_TRACE_SAMPLE_RATE="1"' : ''}
${formData.features.apm ? 'export DD_RUNTIME_METRICS_ENABLED=true' : ''}
${formData.features.apm ? 'export DD_PROFILING_ENABLED=true' : ''}
${formData.features.threatProtection ? 'export DD_APPSEC_ENABLED=true' : ''}
${formData.features.codeSecurityProfiling ? 'export DD_IAST_ENABLED=true' : ''}
${formData.features.softwareCompositionAnalysis ? 'export DD_APPSEC_SCA_ENABLED=true' : ''}

tee "$DATADOG_ENV_FILE" >/dev/null <<EOF
# Auto‑generated by install_datadog.sh on $(date -Iseconds)
export ENV_NAME="${formData.env}"
${formData.features.apm ? 'export DD_LOGS_INJECTION=true' : ''}
${formData.features.apm ? 'export DD_TRACE_SAMPLE_RATE="1"' : ''}
${formData.features.apm ? 'export DD_RUNTIME_METRICS_ENABLED=true' : ''}
${formData.features.apm ? 'export DD_PROFILING_ENABLED=true' : ''}
${formData.features.threatProtection ? 'export DD_APPSEC_ENABLED=true' : ''}
${formData.features.codeSecurityProfiling ? 'export DD_IAST_ENABLED=true' : ''}
${formData.features.softwareCompositionAnalysis ? 'export DD_APPSEC_SCA_ENABLED=true' : ''}
EOF

chmod 644 "$DATADOG_ENV_FILE"
source "$DATADOG_ENV_FILE"

# Install the Datadog Agent
DD_API_KEY="$DD_API_KEY" \\
DD_SITE="$DD_SITE" \\
DD_ENV="$ENV_NAME" \\
${formData.features.apm ? 'DD_APM_INSTRUMENTATION_ENABLED=host \\' : ''}
${apmInstrumentationLibraries}
${formData.features.cloudWorkloadSecurity ? 'DD_RUNTIME_SECURITY_CONFIG_ENABLED=true \\' : ''}
${formData.features.containerHostVulnerabilityManagement ? 'DD_SBOM_CONTAINER_IMAGE_ENABLED=true \\' : ''}
${formData.features.containerHostVulnerabilityManagement ? 'DD_SBOM_HOST_ENABLED=true \\' : ''}
bash -c "$(curl -L https://install.datadoghq.com/scripts/install_script_agent7.sh)"

# Append custom configuration to datadog.yaml
cat <<EOF > /etc/datadog-agent/datadog.yaml

## Custom Configuration
api_key: $DD_API_KEY
site: $DD_SITE
env: $ENV_NAME

## Logs
logs_enabled: ${formData.features.logs}
${formData.features.logs ? `logs_config:
  container_collect_all: true
  auto_multi_line_detection: true` : ''}

## APM
apm_config:
  enabled: ${formData.features.apm}

## Process Monitoring
process_config:
  process_collection:
    enabled: ${formData.features.processAgent}

${formData.features.cloudSecurityPostureManagement ? `## Cloud Security Posture Management
compliance_config:
  enabled: true
  host_benchmarks:
    enabled: true` : ''}

${formData.features.cloudWorkloadSecurity ? `## Cloud Workload Security
runtime_security_config:
  enabled: true` : ''}

${formData.features.sbom ? `## SBOM + CSM(container,host) Vulnerabilities
sbom:
  enabled: true
  container_image:
    enabled: true
  host:
    enabled: true` : ''}

${formData.features.otlp ? `## OTLP
otlp_config:
  logs:
    enabled: true
  receiver:
    protocols:
      grpc:
        endpoint: localhost:4317
      http:
        endpoint: localhost:4318` : ''}

EOF

${formData.features.cloudWorkloadSecurity || formData.features.cloudSecurityPostureManagement ? `# Append custom configuration to security-agent.yaml
cat <<EOF > /etc/datadog-agent/security-agent.yaml

${formData.features.cloudWorkloadSecurity ? `## CWS
runtime_security_config: 
  enabled: true` : ''}

${formData.features.cloudSecurityPostureManagement ? `## CSPM
compliance_config:
  enabled: true
  host_benchmarks:
    enabled: true` : ''}

EOF` : ''}

${formData.features.universalServiceMonitoring || formData.features.networkMonitoring || formData.features.processAgent || formData.features.cloudWorkloadSecurity ? `# Append custom configuration to system-probe.yaml
cat <<EOF > /etc/datadog-agent/system-probe.yaml

${formData.features.universalServiceMonitoring ? `## Universal Service Monitoring
service_monitoring_config:
  enabled: true
  process_service_inference:
    enabled: true` : ''}

${formData.features.networkMonitoring ? `## Network Performance Monitoring
network_config:
  enabled: true` : ''}

${formData.features.processAgent ? `## Process Monitoring I/O Stats
system_probe_config:
  process_config:
    enabled: true` : ''}

${formData.features.cloudWorkloadSecurity ? `## Cloud Security Management
runtime_security_config: 
  enabled: true
  remote_configuration:
    enabled: true` : ''}

EOF` : ''}

${formData.advancedOptions.collectAllLogs ? `# Configure the Agent to collect all .log files on the system
# Configure the Agent to collect all .log files on the machine (prunes pseudo/ephemeral FS)
mkdir -p /etc/datadog-agent/conf.d/all_logs.d

# Find all unique directories that contain *.log files across the system,
# skipping pseudo/ephemeral filesystems and container overlay paths.
log_dirs=$(
  find / \
    \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \
       -o -path /var/lib/docker/overlay2 -o -path /var/lib/docker/aufs -o -path /var/lib/containerd \) -prune -o \
    -type f -name "*.log" -print 2>/dev/null \
  | xargs -r -I{} dirname "{}" \
  | sort -u
)

# Begin the logs configuration file
echo "logs:" > /etc/datadog-agent/conf.d/all_logs.d/conf.yaml

# Loop through each directory and create a log config entry
echo "$log_dirs" | while IFS= read -r dir
do
    service_name=$(basename "$dir")
    source_name=$(basename "$dir")

    cat <<EOF >> /etc/datadog-agent/conf.d/all_logs.d/conf.yaml
  - type: file
    path: "$dir/*.log"
    service: "$service_name"
    source: "$source_name"
EOF
done` : ''}

${formData.advancedOptions.updateLogPermissions ? `
# Check if 'setfacl' is already installed
if ! command -v setfacl >/dev/null 2>&1; then
    echo "ACL (setfacl) not found. Attempting to install..."
    
    # Detect which package manager is available
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install -y acl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y acl
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install acl
    else
        echo "Cannot determine your package manager. Please install 'acl' manually."
        exit 1
    fi
    
    # Double-check setfacl is now installed
    if ! command -v setfacl >/dev/null 2>&1; then
        echo "Failed to install ACL. Please install the 'acl' package manually."
        exit 1
    fi
else
    echo "ACL is already installed."
fi

# Update permissions for .log files
#    Set default ACLs so existing files/dirs inherit dd-agent's rx permissions:
echo "Setting ACLs for dd-agent on /var/log..."
sudo setfacl -Rm u:dd-agent:rx /var/log

#    Set default ACLs so new files/dirs inherit dd-agent's rx permissions:
sudo setfacl -Rdm u:dd-agent:rx /var/log
echo "ACLs have been set. Datadog log collection configuration updated."

# 1. Find all *.log directories across the system
log_dirs=$(
  find / \
    \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \
       -o -path /var/lib/docker/overlay2 -o -path /var/lib/docker/aufs -o -path /var/lib/containerd \) -prune -o \
    -type f -name "*.log" -print 2>/dev/null \
  | xargs -r -I{} dirname "{}" \
  | sort -u
)

# 2. Iterate over each directory, set ACLs
for dir in $log_dirs; do
  echo "Setting ACL for .log files in: $dir"
  setfacl -m u:dd-agent:rx "$dir" 2>/dev/null || true
  setfacl -m u:dd-agent:rx "$dir"/*.log 2>/dev/null || true
  echo "--------------------------------------"
done` : ''}

# Restart the Datadog Agent to apply changes
echo "Restarting the Datadog Agent..."
if command -v systemctl >/dev/null; then
    sudo systemctl restart datadog-agent
    echo "Restarting the Datadog Agent with... sudo systemctl restart datadog-agent"
elif command -v service >/dev/null; then
    sudo service datadog-agent restart
    echo "Restarting the Datadog Agent with... sudo service datadog-agent restart"
else
    echo "Could not determine how to restart the Datadog Agent. Please restart it manually."
fi

sleep 5

# Get Datadog Agent Status
sudo datadog-agent status

# Show contents of the all-logs config if present
if [ -f "/etc/datadog-agent/conf.d/all_logs.d/conf.yaml" ]; then
  echo ""
  echo "----- /etc/datadog-agent/conf.d/all_logs.d/conf.yaml -----"
  sudo cat /etc/datadog-agent/conf.d/all_logs.d/conf.yaml
  echo "----------------------------------------------------------"
else
  echo "All-logs config not found at /etc/datadog-agent/conf.d/all_logs.d/conf.yaml (Collect All Logs may be disabled)."
fi

echo "Datadog Agent installation and configuration complete."

echo "Restart Datadog Agent with command... sudo systemctl restart datadog-agent or sudo service datadog-agent restart"
echo "Get Datadog Agent Status with command... sudo datadog-agent status"
echo "Check your log collection files... sudo cat /etc/datadog-agent/conf.d/all_logs.d"
echo "PLEASE RESTART THE DATADOG AGENT AND YOUR APPLICATION SERVICE TO SEE DATA!"

`

      // *** ADDED: Remove empty lines before setting the final script
      script = script
        .split('\n')
        .filter(line => line.trim().length > 0)
        .join('\n')


      setGeneratedScript(script)
    } else if (formData.os === 'windows') {
      let script = `
# Prompt for Datadog site selection
$ddSite = "${formData.site}"

# Prompt for Datadog API key
$apiKey = "${formData.apiKey}"

# Prompt for Environment Name
$environmentName = "${formData.env}"

# Construct tags from input
$env:DD_TAGS = "env:$environmentName"

# Step 3: Install the Datadog Agent
Write-Host "Installing Datadog Agent using Install-Datadog.ps1"

# Mandatory flags
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
$env:DD_API_KEY         = "$apiKey"
$env:DD_SITE            = "$ddSite"
$env:DD_ENV             = "$environmentName"
$env:DD_REMOTE_UPDATES  = "true"

# Ensure we are elevated
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Please run PowerShell as Administrator."
  exit 1
}

# Optional APM automatic instrumentation for IIS /.NET
if (${formData.features.apm}) {
    $env:DD_APM_INSTRUMENTATION_ENABLED  = "iis"
    $env:DD_APM_INSTRUMENTATION_LIBRARIES = "dotnet:3"   # build this string dynamically from your formData if needed
}

# Download & run the official installer wrapper
(New-Object System.Net.WebClient).DownloadFile(
  'https://install.datadoghq.com/Install-Datadog.ps1',
  'C:\Windows\Temp\Install-Datadog.ps1'
)
C:\Windows\Temp\Install-Datadog.ps1

# Step 4: Configure the Datadog Agent
Write-Host "Configuring Datadog Agent"
$configFile = "C:\\ProgramData\\Datadog\\datadog.yaml"

# Check if the configuration file exists
if (Test-Path $configFile) {
    $configContent = Get-Content $configFile
} else {
    $configContent = @()
    New-Item -Path $configFile -ItemType File -Force
}

# Update the datadog.yaml file with the provided content

# Path to the datadog.yaml file
Write-Host "Updating datadog.yaml file"
$configFile = "C:\\ProgramData\\Datadog\\datadog.yaml"

# Content to write to datadog.yaml
$yamlContent = @"
## Official Source: https://github.com/DataDog/datadog-agent/blob/main/pkg/config/config_template.yaml
##
## Edit this in file location :
## Linux: /etc/datadog-agent/datadog.yaml
## Windows: %ProgramData%\\Datadog\\datadog.yaml
api_key: $apiKey
site: $ddSite
env: $environmentName

## Tags https://docs.datadoghq.com/tagging/
tags:
  - env: $environmentName

## Logs 
logs_enabled: ${formData.features.logs}
logs_config:
  auto_multi_line_detection: true

## APM
apm_config:
  enabled: true

## Process Monitoring
process_config:
  process_collection:
    enabled: ${formData.features.processAgent}

## OTLP
otlp_config:
  receiver:
    protocols:
      grpc:
        endpoint: localhost:4317
      http:
        endpoint: localhost:4318
  logs:
    enabled: ${formData.features.otlp}

## Host Vulnerability Scanning
sbom:
  enabled: ${formData.features.sbom}
  host:
    enabled: ${formData.features.sbom}

## If using Windows EC2 Auto Scaling Group https://docs.datadoghq.com/agent/faq/ec2-use-win-prefix-detection/ 
ec2_use_windows_prefix_detection: true
"@

# Write the content to the datadog.yaml file
$yamlContent | Set-Content -Path $configFile -Encoding UTF8

# Update the security-agent.yaml file with the provided content

# Path to the security-agent.yaml file
Write-Host "Updating security-agent.yaml file"
$securityConfigFile = "C:\\ProgramData\\Datadog\\security-agent.yaml"

# Content to write to security-agent.yaml
$securityYamlContent = @"
runtime_security_config:
  enabled: ${formData.features.cloudWorkloadSecurity}
  # File Integrity Monitoring (FIM)
  fim_enabled: ${formData.features.cloudWorkloadSecurity}
"@

# Write the content to the security-agent.yaml file
$securityYamlContent | Set-Content -Path $securityConfigFile -Encoding UTF8

# Update the system-probe.yaml file with the provided content

# Path to the system-probe.yaml file
Write-Host "Updating system-probe.yaml file"
$systemprobeConfigFile = "C:\\ProgramData\\Datadog\\system-probe.yaml"

# Content to write to system-probe.yaml
$systemprobeYamlContent = @"
## Universal Service Monitoring
service_monitoring_config:
  enabled: ${formData.features.universalServiceMonitoring}

## Network Performance Monitoring
network_config:
  enabled: ${formData.features.networkMonitoring}

## Process Monitoring I/O Stats
system_probe_config:
  process_config:
    enabled: ${formData.features.processAgent}

## Cloud Security Management
runtime_security_config: 
  enabled: ${formData.features.cloudWorkloadSecurity}
  # File Integrity Monitoring (FIM)
  fim_enabled: ${formData.features.cloudWorkloadSecurity}
"@

# Write the content to the system-probe.yaml file
$systemprobeYamlContent | Set-Content -Path $systemprobeConfigFile -Encoding UTF8

${formData.advancedOptions.collectWindowsEventLogs ? `
# Update the win32_event_log.d/conf.yaml file with the provided content
# Path to the win32_event_log.d/conf.yaml file
Write-Host "Updating win32_event_log.d/conf.yaml file"
$windowsEventLogConfigFile = "C:\\ProgramData\\Datadog\\conf.d\\win32_event_log.d\\conf.yaml"

# Content to write to win32_event_log.d/conf.yaml
$windowsEventLogYamlContent = @"
logs:
  - type: windows_event
    channel_path: Security
    source: windows.events
    service: windows-security

  - type: windows_event
    channel_path: System
    source: windows.events
    service: windows-system
  
  - type: windows_event
    channel_path: Application
    source: windows.events
    service: windows-application
"@

# Write the content to the win32_event_log.d/conf.yaml file
$windowsEventLogYamlContent | Set-Content -Path $windowsEventLogConfigFile -Encoding UTF8
` : ''}

${formData.advancedOptions.collectIISLogs ? `
# Update the iis.d/conf.yaml file with the provided content
# Path to the iis.d/conf.yaml file
Write-Host "Updating iis.d/conf.yaml file"
$iisLogConfigFile = "C:\\ProgramData\\Datadog\\conf.d\\iis.d\\conf.yaml"

# Content to write to iis.d/conf.yaml
$iisYamlContent = @"
init_config:

instances:
  - host: .

logs:
  - type: file
    path: C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*
    service: iis
    source: iis
  - type: file
    path: C:\\inetpub\\logs\\LogFiles\\W3SVC2\\u_ex*
    service: iis
    source: iis
  - type: file
    path: C:\\inetpub\\logs\\LogFiles\\W3SVC*\\u_ex*
    service: iis
    source: iis
"@

# Write the content to the iis.d/conf.yaml file
$iisYamlContent | Set-Content -Path $iisLogConfigFile -Encoding UTF8
` : ''}

${formData.advancedOptions.collectAllWindowsLogs ? `
# Collect all .log files across the machine and grant permissions
Write-Host "Configuring collection of ALL .log files (this may take a while)..."
$allLogsDir = "C:\\ProgramData\\Datadog\\conf.d\\all_logs.d"
New-Item -ItemType Directory -Path $allLogsDir -Force | Out-Null
$allLogsConf = Join-Path $allLogsDir "conf.yaml"

# Enumerate unique directories containing .log files across ALL drives (exclude Datadog paths)
$driveRoots = [System.IO.DriveInfo]::GetDrives() |
   Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } |
   Select-Object -ExpandProperty RootDirectory |
   ForEach-Object { $_.FullName }

$logDirs = foreach ($root in $driveRoots) {
  Get-ChildItem -Path $root -Filter *.log -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\ProgramData\\Datadog\\' } |
    Select-Object -ExpandProperty DirectoryName
}

$logDirs = $logDirs | Sort-Object -Unique

# Build YAML
$yamlLines = @("logs:")
foreach ($dir in $logDirs) {
  $svc = Split-Path $dir -Leaf
  $yamlLines += "  - type: file"
  $yamlLines += "    path: $dir\\*.log"
  $yamlLines += "    service: $svc"
  $yamlLines += "    source: $svc"
}
[string]::Join([Environment]::NewLine, $yamlLines) | Set-Content -Path $allLogsConf -Encoding UTF8

# Grant read permissions to the Datadog service account on these directories
try {
  $ddUser  = "ddagentuser"
  $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $prop    = [System.Security.AccessControl.PropagationFlags]::None
  $rights  = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::ListDirectory

  foreach ($dir in $logDirs) {
    try {
      $acl  = Get-Acl -Path $dir
      $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($ddUser, $rights, $inherit, $prop, "Allow")
      $acl.AddAccessRule($rule) | Out-Null
      Set-Acl -Path $dir -AclObject $acl

      # Ensure existing .log files also have read perms
      Get-ChildItem -Path $dir -Filter *.log -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
          $fAcl  = Get-Acl -Path $_.FullName
          $fRule = New-Object System.Security.AccessControl.FileSystemAccessRule($ddUser, [System.Security.AccessControl.FileSystemRights]::Read, "Allow")
          $fAcl.AddAccessRule($fRule) | Out-Null
          Set-Acl -Path $_.FullName -AclObject $fAcl
        } catch {
          Write-Warning "ACL update failed for file $($_.FullName): $_"
        }
      }
    } catch {
      Write-Warning "ACL update failed for $dir: $_"
    }
  }
} catch {
  Write-Warning "Could not set ACLs for some directories: $_"
}
` : ''}

# Step 5: Restart the Datadog Agent Service
Write-Host "Restarting Datadog Agent Service"
& "$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe" restart-service

# Wait for services to fully restart
Start-Sleep -Seconds 10  # Adjust the sleep time if necessary

& "$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe" status
& "$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe" launch-gui

# Show contents of the all-logs config if present
$allLogsConf = "C:\\ProgramData\\Datadog\\conf.d\\all_logs.d\\conf.yaml"
if (Test-Path $allLogsConf) {
  Write-Host ""
  Write-Host "----- $allLogsConf -----"
  Get-Content -Path $allLogsConf | Out-Host
  Write-Host "------------------------"
} else {
  Write-Host "All-logs config not found at $allLogsConf (Collect All .log Files may be disabled)."
}

Write-Host "Restart the Datadog Agent Service with... & \`\"$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe\`\" restart-service"
Write-Host "Status of Datadog Agent Service with... & \`\"$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe\`\" status"
Write-Host "GUI of Datadog Agent Service with... & \`\"$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe\`\" launch-gui"
Write-Host "Check all your log collection files... Get-Content -Path "C:\\ProgramData\\Datadog\\conf.d\\all_logs.d\\conf.yaml" | Out-Host"

`
      // *** ADDED: Remove empty lines before setting the final script
      script = script
        .split('\n')
        .filter(line => line.trim().length > 0)
        .join('\n')

      setGeneratedScript(script)
    } else if (formData.os === 'docker') {
      // *** UPDATED — build APM libraries string for Docker
      const apmInstrumentationLibraries = formData.features.apm
        ? Object.entries(formData.apmInstrumentationLanguages)
            .filter(([_, value]) => value)
            .map(([key, _]) => {
              switch (key) {
                case 'js':
                  return 'js:5'
                case 'python':
                  return 'python:3'
                case 'dotnet':
                  return 'dotnet:3'
                case 'ruby':
                  return 'ruby:2'
                case 'php':
                  return 'php:1'
                default:
                  return `${key}:1`
              }
            })
            .join(',')
        : ''

      // *** UPDATED — detect if any App‑Sec feature is enabled
      const isAppSecSelected =
        formData.features.threatProtection ||
        formData.features.softwareCompositionAnalysis ||
        formData.features.codeSecurityProfiling

      // *** UPDATED — choose the correct pre‑install command
      const preInstallCommand = isAppSecSelected
        ? `DD_APPSEC_ENABLED=true DD_IAST_ENABLED=true DD_APPSEC_SCA_ENABLED=true ${
            apmInstrumentationLibraries ? `DD_APM_INSTRUMENTATION_LIBRARIES=${apmInstrumentationLibraries} ` : ''
          }DD_APM_INSTRUMENTATION_ENABLED=docker DD_NO_AGENT_INSTALL=true bash -c "$(curl -L https://install.datadoghq.com/scripts/install_script_agent7.sh)"`
        : (formData.features.apm
            ? `${apmInstrumentationLibraries ? `DD_APM_INSTRUMENTATION_LIBRARIES=${apmInstrumentationLibraries} ` : ''}DD_APM_INSTRUMENTATION_ENABLED=docker DD_NO_AGENT_INSTALL=true bash -c "$(curl -L https://install.datadoghq.com/scripts/install_script_docker_injection.sh)"`
        : '')

      let script = `
#!/bin/bash

# This is an unofficial Datadog Agent Installation Script
# This is not affiliated with Datadog, please reach out to your Datadog account manager if you have any issues.

set -x

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Please run this script as root or with sudo."
   exit 1
fi

# Insert pre‑install command
${preInstallCommand}

# Create a datadog network
docker network create datadog || true

# Run the Datadog Agent Docker container
docker run -d --name dd-agent \\
--cgroupns host \\
--pid host \\
--network datadog \\
-p 8126:8126/tcp \\
-e DD_API_KEY=${formData.apiKey} \\
-e DD_SITE="${formData.site}" \\
-e DD_ENV="${formData.env}" \\
-e DD_APM_ENABLED=${formData.features.apm} \\
${formData.features.apm ? '-e DD_APM_NON_LOCAL_TRAFFIC=true \\' : ''}
${formData.features.apm ? '-e DD_APM_RECEIVER_SOCKET=/var/run/datadog/apm.socket \\' : ''}
${formData.features.apm ? '-e DD_DOGSTATSD_SOCKET=/var/run/datadog/dsd.socket \\' : ''}
${formData.features.apm ? '-e DD_DOGSTATSD_NON_LOCAL_TRAFFIC=true \\' : ''}
${formData.features.apm ? '-e DD_LOGS_INJECTION=true \\' : ''}
${formData.features.apm ? '-e DD_TRACE_SAMPLE_RATE="1" \\' : ''}
${formData.features.apm ? '-e DD_PROFILING_ENABLED=true \\' : ''}
-e DD_APPSEC_ENABLED=${formData.features.threatProtection} \\
-e DD_IAST_ENABLED=${formData.features.codeSecurityProfiling} \\
-e DD_APPSEC_SCA_ENABLED=${formData.features.softwareCompositionAnalysis} \\
${formData.features.otlp ? `-e DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT=0.0.0.0:4317 \\
-e DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_HTTP_ENDPOINT=0.0.0.0:4318 \\
-e DD_OTLP_CONFIG_LOGS_ENABLED=true \\` : ''}
-e DD_LOGS_ENABLED=${formData.features.logs} \\
-e DD_LOGS_CONFIG_CONTAINER_COLLECT_ALL=${formData.features.logs} \\
-e DD_PROCESS_CONFIG_CONTAINER_COLLECTION_ENABLED=true \\
-v /opt/datadog-agent/run:/opt/datadog-agent/run:rw \\
-e DD_PROCESS_CONFIG_PROCESS_COLLECTION_ENABLED=${formData.features.processAgent} \\
-v /etc/passwd:/etc/passwd:ro \\
-e DD_SYSTEM_PROBE_NETWORK_ENABLED=${formData.features.networkMonitoring} \\
-e DD_PROCESS_AGENT_ENABLED=${formData.features.processAgent} \\
-e DD_COMPLIANCE_CONFIG_ENABLED=${formData.features.cloudSecurityPostureManagement} \\
-e DD_COMPLIANCE_CONFIG_HOST_BENCHMARKS_ENABLED=${formData.features.cloudSecurityPostureManagement} \\
-e DD_RUNTIME_SECURITY_CONFIG_ENABLED=${formData.features.cloudWorkloadSecurity} \\
-e DD_RUNTIME_SECURITY_CONFIG_REMOTE_CONFIGURATION_ENABLED=${formData.features.cloudWorkloadSecurity} \\
-e DD_SYSTEM_PROBE_SERVICE_MONITORING_ENABLED=${formData.features.universalServiceMonitoring} \\
-v /lib/modules:/lib/modules:ro \\
-v /usr/src:/usr/src:ro \\
-v /var/tmp/datadog-agent/system-probe/build:/var/tmp/datadog-agent/system-probe/build \\
-v /var/tmp/datadog-agent/system-probe/kernel-headers:/var/tmp/datadog-agent/system-probe/kernel-headers \\
-v /etc/apt:/host/etc/apt:ro \\
-v /etc/yum.repos.d:/host/etc/yum.repos.d:ro \\
-v /etc/zypp:/host/etc/zypp:ro \\
-v /etc/pki:/host/etc/pki:ro \\
-v /etc/yum/vars:/host/etc/yum/vars:ro \\
-v /etc/dnf/vars:/host/etc/dnf/vars:ro \\
-v /etc/rhsm:/host/etc/rhsm:ro \\
-v /var/run/docker.sock:/var/run/docker.sock:ro \\
-v /var/run/datadog/:/var/run/datadog/ \\
-e HOST_ROOT=/host/root \\
-v /proc/:/host/proc/:ro \\
-v /sys/fs/cgroup/:/host/sys/fs/cgroup:ro \\
-v /var/lib/docker/containers:/var/lib/docker/containers:ro \\
-v /etc/group:/etc/group:ro \\
-v /:/host/root:ro \\
-v /etc/os-release:/etc/os-release \\
-v /sys/kernel/debug:/sys/kernel/debug \\
--security-opt apparmor:unconfined \\
--cap-add=SYS_ADMIN \\
--cap-add=SYS_RESOURCE \\
--cap-add=SYS_PTRACE \\
--cap-add=NET_ADMIN \\
--cap-add=NET_BROADCAST \\
--cap-add=NET_RAW \\
--cap-add=IPC_LOCK \\
--cap-add=CHOWN \\
gcr.io/datadoghq/agent:7


echo "Datadog Agent Docker container started. Please check the container logs for any issues."
echo "You can view the logs by running: sudo docker logs dd-agent"
echo "You can view the status by running: sudo docker exec -it dd-agent agent status"
echo "Put your application containers in the same network as datadog --network datadog"
echo "PLEASE RESTART YOUR APPLICATION SERVICE CONTAINERS TO SEE APM DATA!"

cat <<'SH'
# Application
docker run -d --name app \
              -v /var/run/datadog/:/var/run/datadog/ \
              -e DD_TRACE_AGENT_URL=unix:///var/run/datadog/apm.socket \
              company/app:latest
SH

`
      
      // *** ADDED: Remove empty lines before setting the final script
      script = script
        .split('\n')
        .filter(line => line.trim().length > 0)
        .join('\n')

      setGeneratedScript(script)
    }
  }

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(generatedScript)
      // Optionally show a notification that copy was successful
      console.log('Copied successfully!')
    } catch (error) {
      console.error('Failed to copy text:', error)
    }
  }

  const renderStep = () => {
    switch (step) {
      case 1:
        return (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold">Step 1: Select Platform</h2>
            <RadioGroup value={formData.os} onValueChange={(value) => setFormData((prev) => ({ ...prev, os: value }))} className="flex flex-col space-y-2">
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="linux" id="os-linux" />
                <Label htmlFor="os-linux">Linux</Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="windows" id="os-windows" />
                <Label htmlFor="os-windows">Windows</Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="docker" id="os-docker" />
                <Label htmlFor="os-docker">Docker</Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="kubernetes" id="os-kubernetes" />
                <Label htmlFor="os-kubernetes">Kubernetes</Label>
              </div>
            </RadioGroup>
          </div>
        )
      case 2:
        return (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold">Step 2: Select Datadog Site</h2>
            <Select value={formData.site} onValueChange={(value) => setFormData((prev) => ({ ...prev, site: value }))}>
              <SelectTrigger>
                <SelectValue placeholder="Select Datadog site" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="datadoghq.com">US1 (datadoghq.com)</SelectItem>
                <SelectItem value="us3.datadoghq.com">US3 (us3.datadoghq.com)</SelectItem>
                <SelectItem value="us5.datadoghq.com">US5 (us5.datadoghq.com)</SelectItem>
                <SelectItem value="datadoghq.eu">EU1 (datadoghq.eu)</SelectItem>
                <SelectItem value="ddog-gov.com">US1-FED (ddog-gov.com)</SelectItem>
                <SelectItem value="ap1.datadoghq.com">AP1 (ap1.datadoghq.com)</SelectItem>
              </SelectContent>
            </Select>
            {formData.os === 'kubernetes' && formData.site && (
              <div className="mt-4 p-4 border rounded-md bg-blue-50">
                <h3 className="text-lg font-medium mb-2">Kubernetes Installation</h3>
                <p>For Kubernetes installation, you'll be redirected to the official Datadog website with your selected site.</p>
                <p className="mt-2">After clicking "Next", you'll be taken to:</p>
                <a href={getKubernetesUrl()} target="_blank" rel="noopener noreferrer" className="flex items-center mt-2 text-primary hover:underline">
                  {getKubernetesUrl()}
                  <ExternalLink className="ml-1 h-4 w-4" />
                </a>
              </div>
            )}
          </div>
        )
      case 3:
        return (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold">Step 3: Enter API Key</h2>
            {formData.os === 'kubernetes' ? (
              <div className="p-4 border rounded-md bg-blue-50">
                <h3 className="text-lg font-medium mb-2">Kubernetes Installation</h3>
                <p>Please follow the instructions on the Datadog website that opened in a new tab.</p>
                <p className="mt-2">If you need to access the page again, you can visit:</p>
                <a 
                  href={getKubernetesUrl()} 
                  target="_blank" 
                  rel="noopener noreferrer" 
                  className="flex items-center mt-2 text-primary hover:underline"
                >
                  {getKubernetesUrl()}
                  <ExternalLink className="ml-1 h-4 w-4" />
                </a>
                <Button 
                  type="button" 
                  className="mt-4" 
                  onClick={() => window.open(getKubernetesUrl(), '_blank')}
                >
                  Open Kubernetes Installation Guide
                </Button>
              </div>
            ) : (
            <div>
              <Label htmlFor="apiKey">API Key</Label>
              <Input
                type="text"
                id="apiKey"
                name="apiKey"
                value={formData.apiKey}
                onChange={handleInputChange}
                placeholder="Enter your Datadog API key"
              />
            </div>
          )}
          </div>
        )
      default:
        return (
          <div className="space-y-6">
            {formData.os === 'kubernetes' ? (
              <div className="p-4 border rounded-md bg-blue-50">
                <h3 className="text-lg font-medium mb-2">Kubernetes Installation</h3>
                <p>Please follow the instructions on the Datadog website that opened in a new tab.</p>
                <p className="mt-2">If you need to access the page again, you can visit:</p>
                <a 
                  href={getKubernetesUrl()} 
                  target="_blank" 
                  rel="noopener noreferrer" 
                  className="flex items-center mt-2 text-primary hover:underline"
                >
                  {getKubernetesUrl()}
                  <ExternalLink className="ml-1 h-4 w-4" />
                </a>
                <Button 
                  type="button" 
                  className="mt-4" 
                  onClick={() => window.open(getKubernetesUrl(), '_blank')}
                >
                  Open Kubernetes Installation Guide
                </Button>
              </div>
            ) : (
              <>
            <h2 className="text-xl font-semibold">Additional Configuration</h2>
            <div>
              <Label htmlFor="env">Environment Name (eg: production, staging, development, poc)</Label>
              <Input type="text" id="env" name="env" value={formData.env} onChange={handleInputChange} placeholder="Enter the environment" />
            </div>
            <div className="space-y-4">
              <div>
                <Label className="text-lg font-semibold">Monitoring Features</Label>
                <div className="grid grid-cols-2 gap-2 mt-2">
                  <FeatureCheckbox
                    id="logs"
                    label="Logs"
                    checked={formData.features.logs}
                    onCheckedChange={() => handleFeatureToggle('logs')}
                    docLink="https://docs.datadoghq.com/logs/"
                  />
                  <FeatureCheckbox
                    id="apm"
                    label="APM"
                    checked={formData.features.apm}
                    onCheckedChange={() => handleFeatureToggle('apm')}
                    docLink="https://docs.datadoghq.com/tracing/"
                  />
                    {formData.features.apm && (formData.os === 'linux' || formData.os === 'docker') && (
                    <div className="col-span-2 ml-6 space-y-2">
                      <Label className="text-sm font-semibold">APM Instrumentation Languages</Label>
                      <div className="grid grid-cols-2 gap-2">
                        <FeatureCheckbox
                          id="apm-java"
                          label="Java"
                          checked={formData.apmInstrumentationLanguages.java}
                          onCheckedChange={() => handleApmLanguageToggle('java')}
                          docLink="https://docs.datadoghq.com/tracing/setup_overview/setup/java/"
                        />
                        <FeatureCheckbox
                          id="apm-js"
                          label="NodeJS"
                          checked={formData.apmInstrumentationLanguages.js}
                          onCheckedChange={() => handleApmLanguageToggle('js')}
                          docLink="https://docs.datadoghq.com/tracing/setup_overview/setup/nodejs/"
                        />
                        <FeatureCheckbox
                          id="apm-python"
                          label="Python"
                          checked={formData.apmInstrumentationLanguages.python}
                          onCheckedChange={() => handleApmLanguageToggle('python')}
                          docLink="https://docs.datadoghq.com/tracing/setup_overview/setup/python/"
                        />
                        <FeatureCheckbox
                          id="apm-dotnet"
                          label=".NET"
                          checked={formData.apmInstrumentationLanguages.dotnet}
                          onCheckedChange={() => handleApmLanguageToggle('dotnet')}
                          docLink="https://docs.datadoghq.com/tracing/setup_overview/setup/dotnet/"
                        />
                        <FeatureCheckbox
                          id="apm-ruby"
                          label="Ruby"
                          checked={formData.apmInstrumentationLanguages.ruby}
                          onCheckedChange={() => handleApmLanguageToggle('ruby')}
                          docLink="https://docs.datadoghq.com/tracing/setup_overview/setup/ruby/"
                        />
                        <FeatureCheckbox
                          id="apm-php"
                          label="PHP"
                          checked={formData.apmInstrumentationLanguages.php}
                          onCheckedChange={() => handleApmLanguageToggle('php')}
                          docLink="https://docs.datadoghq.com/tracing/setup_overview/setup/php/"
                        />
                      </div>
                    </div>
                  )}
                  <FeatureCheckbox
                    id="processAgent"
                    label="Process Monitoring"
                    checked={formData.features.processAgent}
                    onCheckedChange={() => handleFeatureToggle('processAgent')}
                    docLink="https://docs.datadoghq.com/infrastructure/process/"
                  />
                  <FeatureCheckbox
                    id="networkMonitoring"
                    label="Network Monitoring"
                    checked={formData.features.networkMonitoring}
                    onCheckedChange={() => handleFeatureToggle('networkMonitoring')}
                    docLink="https://docs.datadoghq.com/network_monitoring/"
                  />
                  <FeatureCheckbox
                    id="universalServiceMonitoring"
                    label="Universal Service Monitoring"
                    checked={formData.features.universalServiceMonitoring}
                    onCheckedChange={() => handleFeatureToggle('universalServiceMonitoring')}
                    docLink="https://docs.datadoghq.com/universal_service_monitoring/"
                  />
                </div>
              </div>

              <div>
                <Label className="text-lg font-semibold">Security Features</Label>
                <div className="grid grid-cols-2 gap-2 mt-2">
                  <FeatureCheckbox
                    id="cloudSecurity"
                    label="Cloud Security"
                    checked={formData.features.cloudSecurityPostureManagement || 
                             formData.features.cloudWorkloadSecurity || 
                             formData.features.containerHostVulnerabilityManagement || 
                             formData.features.sbom}
                    onCheckedChange={() => {
                      handleFeatureToggle('cloudSecurityPostureManagement')
                      handleFeatureToggle('cloudWorkloadSecurity')
                      handleFeatureToggle('containerHostVulnerabilityManagement')
                      handleFeatureToggle('sbom')
                    }}
                    docLink="https://docs.datadoghq.com/security/cloud_security_management"
                  />
                  <FeatureCheckbox
                    id="applicationSecurity"
                    label="Application Security"
                    checked={formData.features.threatProtection || 
                             formData.features.softwareCompositionAnalysis || 
                             formData.features.codeSecurityProfiling}
                    onCheckedChange={() => {
                      handleFeatureToggle('threatProtection')
                      handleFeatureToggle('softwareCompositionAnalysis')
                      handleFeatureToggle('codeSecurityProfiling')
                    }}
                    docLink="https://docs.datadoghq.com/security/application_security/"
                  />
                </div>
              </div>

              <div>
                <Label className="text-lg font-semibold">Other Features</Label>
                <div className="grid grid-cols-2 gap-2 mt-2">
                  <FeatureCheckbox
                    id="otlp"
                    label="OpenTelemetry Protocol OTLP"
                    checked={formData.features.otlp}
                    onCheckedChange={() => handleFeatureToggle('otlp')}
                    docLink="https://docs.datadoghq.com/opentelemetry/"
                  />
                </div>
              </div>
            </div>
            {formData.os !== 'docker' && (
              <>
                <div className="my-6 border-t border-gray-200"></div>
                <div className="space-y-2">
                  <Label>Advanced Options</Label>
                  {formData.os === 'linux' && (
                    <>
                      <div className="flex items-center space-x-2">
                        <Checkbox id="collectAllLogs" checked={formData.advancedOptions.collectAllLogs} onCheckedChange={() => handleAdvancedOptionToggle('collectAllLogs')} />
                        <Label htmlFor="collectAllLogs">Collect All Logs</Label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Checkbox id="updateLogPermissions" checked={formData.advancedOptions.updateLogPermissions} onCheckedChange={() => handleAdvancedOptionToggle('updateLogPermissions')} />
                        <Label htmlFor="updateLogPermissions">Update Log Permissions</Label>
                      </div>
                    </>
                  )}
                  {formData.os === 'windows' && (
                    <>
                      <div className="flex items-center space-x-2">
                        <Checkbox
                          id="collectAllWindowsLogs"
                          checked={formData.advancedOptions.collectAllWindowsLogs}
                          onCheckedChange={() => handleAdvancedOptionToggle('collectAllWindowsLogs')}
                        />
                        <Label htmlFor="collectAllWindowsLogs">Collect All .log Files</Label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Checkbox id="collectIISLogs" checked={formData.advancedOptions.collectIISLogs} onCheckedChange={() => handleAdvancedOptionToggle('collectIISLogs')} />
                        <Label htmlFor="collectIISLogs">Collect IIS Logs</Label>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Checkbox id="collectWindowsEventLogs" checked={formData.advancedOptions.collectWindowsEventLogs} onCheckedChange={() => handleAdvancedOptionToggle('collectWindowsEventLogs')} />
                        <Label htmlFor="collectWindowsEventLogs">Collect Windows Event Logs</Label>
                      </div>
                    </>
                  )}
                </div>
                </>
              )}
              </>
            )}
          </div>
        )
    }
  }

  return (
    <div className="container mx-auto p-4 max-w-3xl">
      <h1 className="text-2xl font-bold mb-4">Datadog Agent Installation Script</h1>
      <div className="mb-4">
        <div className="flex items-center">
          {[1,2,3,4].map((s) => (
            <div key={s} className="flex items-center">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center ${s === step ? 'bg-primary text-primary-foreground' : 'bg-muted'}`}>
                {s}
              </div>
              {s < 4 && <div className={`h-1 w-8 ${s < step ? 'bg-primary' : 'bg-muted'}`} />}
            </div>
          ))}
        </div>
      </div>
      <form className="space-y-6">
        {renderStep()}
        <div className="flex justify-between mt-6">
          {step > 1 && (
            <Button type="button" onClick={prevStep}>
              Previous
            </Button>
          )}
          {step < 4 ? (
            <Button type="button" onClick={nextStep}>
              Next
            </Button>
          ) : (
            <Button 
              type="button" 
              onClick={generateScript}
              disabled={formData.os === 'kubernetes'}
            >
              Generate Script
            </Button>
          )}
        </div>
      </form>
      {generatedScript && formData.os !== 'kubernetes' && (
        <div className="mt-8 relative">
          <h2 className="text-xl font-bold mb-2">Generated Installation Script</h2>
          <Button
            type="button"
            variant="outline"
            size="icon"
            className="absolute top-8 right-2 z-10"
            onClick={copyToClipboard}
            aria-label="Copy generated script"
          >
            <Copy className="h-4 w-4" />
          </Button>
          <Textarea ref={scriptRef} value={generatedScript} readOnly className="h-96 font-mono text-sm pr-10" />
        </div>
      )}
      {generatedScript && formData.os !== 'kubernetes' && (
        <div className="mt-8">
          <h2 className="text-xl font-bold mb-2">How to Execute the Script</h2>
          <ol className="list-decimal list-inside space-y-2">
            <li>Copy the generated script from the "Generated Installation Script" textarea above.</li>
            {formData.os === 'docker' ? (
              <>
                <li>Open a terminal on your Docker host machine.</li>
                <li>Paste the copied script into a new file, for example, <code>datadog.sh</code>.</li>
                <li>Make the script executable by running: <pre className="bg-muted p-2 mt-1 rounded">chmod +x datadog.sh</pre></li>
                <li>Execute the script with: <pre className="bg-muted p-2 mt-1 rounded">sudo ./datadog.sh</pre></li>
              </>
            ) : (
              <>
                <li>Open a text editor on your {formData.os === 'linux' ? 'Linux' : 'Windows'} machine.</li>
                <li>Paste the copied script into the text editor.</li>
                <li>Save the file with a {formData.os === 'linux' ? '.sh' : '.ps1'} extension (e.g. {formData.os === 'linux' ? 'datadog.sh'  : 'datadog.ps1'}).</li>
                <li>Open a {formData.os === 'linux' ? 'terminal' : 'PowerShell window'} on your machine.</li>
                <li>Navigate to the directory where you saved the script using the cd command.</li>
                {formData.os === 'linux' ? (
                  <>
                    <li>Make the script executable by running the following command:
                      <pre className="bg-muted p-2 mt-1 rounded">chmod +x datadog.sh</pre>
                    </li>
                    <li>Execute the script with root privileges using sudo:
                      <pre className="bg-muted p-2 mt-1 rounded">sudo ./datadog.sh</pre>
                    </li>
                  </>
                ) : (
                  <li>Execute the script with administrator privileges:
                    <pre className="bg-muted p-2 mt-1 rounded">powershell -ExecutionPolicy Bypass -File .\datadog.ps1</pre>
                  </li>
                )}
              </>
            )}
            <li>Follow any prompts or instructions provided by the script during execution.</li>
            <li>Once the script completes, verify that the Datadog Agent is running:
              <pre className="bg-muted p-2 mt-1 rounded">
                {formData.os === 'linux' ? 'sudo datadog-agent status' : formData.os === 'windows' ? '& "$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe" status' : 'sudo docker exec -it dd-agent agent status'}
              </pre>
            </li>
          </ol>
          <p className="mt-4 text-red-600 font-semibold">
            Warning: Always review scripts before running them with elevated privileges. Ensure you trust the source and understand the actions the script will perform on your system.
          </p>
          
          {formData.os === 'docker' && (
            <div className="mt-8">
              <h2 className="text-xl font-bold mb-2">Run on Docker Compose</h2>
              <p className="mb-4">
                If you prefer to use Docker Compose to manage your containers, you can easily convert the Docker run command to a Docker Compose file. Follow these steps:
              </p>
              <ol className="list-decimal list-inside space-y-2">
                <li>Copy the entire Docker run command from the generated script.</li>
                <li>Visit <a href="https://www.composerize.com/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">https://www.composerize.com/</a>.</li>
                <li>Composerize will automatically convert the command into a Docker Compose YAML format.</li>
              </ol>
              <p className="mt-4">
                Using Docker Compose can make it easier to manage and update your Datadog Agent configuration, especially if you're running multiple containers or services.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

interface FeatureCheckboxProps {
  id: string
  label: string
  checked: boolean
  onCheckedChange: () => void
  docLink: string
}

function FeatureCheckbox({ id, label, checked, onCheckedChange, docLink }: FeatureCheckboxProps) {
  return (
    <div className="flex items-center space-x-2">
      <Checkbox id={id} checked={checked} onCheckedChange={onCheckedChange} />
      <Label htmlFor={id}>{label}</Label>
      <a href={docLink} target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary/80">
        <ExternalLink className="h-4 w-4" />
      </a>
    </div>
  )
}
