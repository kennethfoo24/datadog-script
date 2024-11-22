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

export default function EnhancedDatadogScriptGenerator() {
  const [step, setStep] = useState(1)
  const [formData, setFormData] = useState({
    os: '',
    site: '',
    apiKey: '',
    serviceName: 'default_service',
    source: 'default_source',
    env: 'default_env',
    features: {
      logs: true,
      apm: true,
      processAgent: true,
      networkMonitoring: true,
      cloudSecurityPostureManagement: true,
      cloudWorkloadSecurity: true,
      sbom: true,
      otlp: true,
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
    },
    advancedOptions: {
      collectAllLogs: true,
      updateLogPermissions: true,
    },
  })

  const [generatedScript, setGeneratedScript] = useState('')
  const scriptRef = useRef<HTMLTextAreaElement>(null)
  const singleCommandRef = useRef<HTMLTextAreaElement>(null)

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
        [language]: !prev.apmInstrumentationLanguages[language as keyof typeof prev.apmInstrumentationLanguages] 
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
      alert("Please select an operating system.")
      return
    }
    if (step === 2 && !formData.site) {
      alert("Please select a Datadog site.")
      return
    }
    if (step === 3 && !formData.apiKey) {
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
      const apmInstrumentationLibraries = formData.features.apm
        ? `DD_APM_INSTRUMENTATION_LIBRARIES=${Object.entries(formData.apmInstrumentationLanguages)
            .filter(([_, value]) => value)
            .map(([key, _]) => `${key}:${key === 'js' ? '5' : key === 'python' ? '2' : key === 'dotnet' ? '3' : key === 'ruby' ? '2' : '1'}`)
            .join(',')} \\`
        : ''

      const script = `#!/bin/bash

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Please run this script as root or with sudo."
   exit 1
fi

# Datadog site and API key
DD_SITE="${formData.site}"
DD_API_KEY="${formData.apiKey}"

# Service details
SERVICE_NAME="${formData.serviceName}"
SOURCE_NAME="${formData.source}"
ENV_NAME="${formData.env}"

# Install the Datadog Agent
DD_API_KEY="$DD_API_KEY" \\
DD_SITE="$DD_SITE" \\
DD_ENV="$ENV_NAME" \\
${formData.features.apm ? 'DD_APM_INSTRUMENTATION_ENABLED=host \\' : ''}
${apmInstrumentationLibraries}
DD_LOGS_INJECTION=true \\
DD_TRACE_SAMPLE_RATE="1" \\
DD_RUNTIME_METRICS_ENABLED=true \\
DD_PROFILING_ENABLED=true \\
${formData.features.threatProtection ? 'DD_APPSEC_ENABLED=true \\' : ''}
${formData.features.codeSecurityProfiling ? 'DD_IAST_ENABLED=true \\' : ''}
${formData.features.softwareCompositionAnalysis ? 'DD_APPSEC_SCA_ENABLED=true \\' : ''}
${formData.features.cloudWorkloadSecurity ? 'DD_RUNTIME_SECURITY_CONFIG_ENABLED=true \\' : ''}
${formData.features.containerHostVulnerabilityManagement ? 'DD_SBOM_CONTAINER_IMAGE_ENABLED=true \\' : ''}
${formData.features.containerHostVulnerabilityManagement ? 'DD_SBOM_HOST_ENABLED=true \\' : ''}
bash -c "$(curl -L https://install.datadoghq.com/scripts/install_script_agent7.sh)"

# Append custom configuration to datadog.yaml
cat <<EOF >> /etc/datadog-agent/datadog.yaml

## Custom Configuration
api_key: $DD_API_KEY
site: $DD_SITE
env: $ENV_NAME

## Tags
tags:
  - service:$SERVICE_NAME
  - source:$SOURCE_NAME

## Logs
logs_enabled: ${formData.features.logs}
${formData.features.logs ? `logs_config:
  container_collect_all: true
  auto_multi_line_detection: true` : ''}

## APM
apm_config:
  enabled: ${formData.features.apm}
  ${formData.features.apm ? 'apm_instrumentation_enabled: true' : ''}

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

## Remote Configuration
remote_configuration:
  enabled: true

${formData.features.sbom ? `## SBOM + CSM(container,host) Vulnerabilities
sbom:
  enabled: true
  container_image:
    enabled: true
  host:
    enabled: true
container_image:
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

${formData.features.threatProtection ? `## Threat Protection
appsec_config:
  enabled: true` : ''}

${formData.features.softwareCompositionAnalysis ? `## Software Composition Analysis
appsec_sca_config:
  enabled: true` : ''}

${formData.features.codeSecurityProfiling ? `## Code Security Profiling
iast_config:
  enabled: true` : ''}

EOF

${formData.features.cloudWorkloadSecurity || formData.features.cloudSecurityPostureManagement ? `# Append custom configuration to security-agent.yaml
cat <<EOF >> /etc/datadog-agent/security-agent.yaml

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
cat <<EOF >> /etc/datadog-agent/system-probe.yaml

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
mkdir -p /etc/datadog-agent/conf.d/all_logs.d

cat <<EOF > /etc/datadog-agent/conf.d/all_logs.d/conf.yaml
logs:
  - type: file
    path: "*.log"
    service: $SERVICE_NAME
    source: $SOURCE_NAME
  - type: file
    path: /*.log
    service: $SERVICE_NAME
    source: $SOURCE_NAME
  - type: file
    path: /**/*.log
    service: $SERVICE_NAME
    source: $SOURCE_NAME
  - type: file
    path: /**/**/*.log
    service: $SERVICE_NAME
    source: $SOURCE_NAME
  - type: file
    path: /**/**/**/*.log
    service: $SERVICE_NAME
    source: $SOURCE_NAME
  - type: file
    path: /**/**/**/**/*.log
    service: $SERVICE_NAME
    source: $SOURCE_NAME
EOF` : ''}

${formData.advancedOptions.updateLogPermissions ? `# Update permissions for .log files
echo "Updating permissions for .log files..."
find / -type f -name "*.log" 2>/dev/null | while read -r logfile; do
    chmod o+r "$logfile"
done` : ''}

# Restart the Datadog Agent to apply changes
echo "Restarting the Datadog Agent..."
if command -v systemctl >/dev/null; then
    sudo systemctl restart datadog-agent
elif command -v service >/dev/null; then
    sudo service datadog-agent restart
else
    echo "Could not determine how to restart the Datadog Agent. Please restart it manually."
fi

echo "Datadog Agent installation and configuration complete."
`

      setGeneratedScript(script)
    } else {
      // Windows script (unchanged)
      const script = `# Prompt for Datadog site selection
Write-Host "Select your Datadog site:"
Write-Host "1) US1 (Datadog US1)"
Write-Host "2) US3 (Datadog US3)"
Write-Host "3) US5 (Datadog US5)"
Write-Host "4) EU1 (Datadog EU)"
Write-Host "5) US1-FED (Datadog US1 Federal)"
Write-Host "6) AP1 (Datadog AP1)"

$siteSelection = Read-Host "Enter the number corresponding to your site [1]:"
if ([string]::IsNullOrEmpty($siteSelection)) {
    $siteSelection = "1"
}

# Map the selection to the site parameter
switch ($siteSelection) {
    "1" { $ddSite = "datadoghq.com" }
    "2" { $ddSite = "us3.datadoghq.com" }
    "3" { $ddSite = "us5.datadoghq.com" }
    "4" { $ddSite = "datadoghq.eu" }
    "5" { $ddSite = "ddog-gov.com" }
    "6" { $ddSite = "ap1.datadoghq.com" }
    default {
        Write-Host "Invalid selection. Defaulting to US1 (datadoghq.com)."
        $ddSite = "datadoghq.com"
    }
}

Write-Host "Selected Datadog site: $ddSite"

# Prompt for Datadog API key
$apiKey = "${formData.apiKey}"

# Prompt for Service Name
$serviceName = "${formData.serviceName}"

# Prompt for Source Name
$sourceName = "${formData.source}"

# Prompt for Environment Name
$environmentName = "${formData.env}"

# Construct tags from input
$tags = "service:$serviceName,source:$sourceName,env:$environmentName"

# Step 3: Install the Datadog Agent
Write-Host "Installing Datadog Agent"
Start-Process -Wait msiexec -ArgumentList '/passive /i "https://s3.amazonaws.com/ddagent-windows-stable/datadog-agent-7-latest.amd64.msi" APIKEY="$apiKey" SITE="$ddSite" TAGS="$tags"'

# Step 4: Configure the Datadog Agent
Write-Host "Configuring Datadog Agent"
$configFile = "C:\ProgramData\Datadog\datadog.yaml"

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
$configFile = "C:\ProgramData\Datadog\datadog.yaml"

# Content to write to datadog.yaml
$yamlContent = @"
## Official Source: https://github.com/DataDog/datadog-agent/blob/main/pkg/config/config_template.yaml
##
## Edit this in file location :
## Linux: /etc/datadog-agent/datadog.yaml
## Windows: %ProgramData%\Datadog\datadog.yaml
api_key: $apiKey
site: $ddSite
env: $environmentName

## Tags https://docs.datadoghq.com/tagging/
tags:
  - service: $serviceName
  - source: $sourceName
  - env: $environmentName

## Logs 
logs_enabled: ${formData.features.logs}
logs_config:
  auto_multi_line_detection: true

## APM
apm_config:
  enabled: ${formData.features.apm}

## Process Monitoring
process_config:
  process_collection:
    enabled: ${formData.features.processAgent}

## Remote Configuration
remote_configuration:
  enabled: true

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
$securityConfigFile = "C:\ProgramData\Datadog\security-agent.yaml"

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
$systemprobeConfigFile = "C:\ProgramData\Datadog\system-probe.yaml"

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

# Update the win32_event_log.d/conf.yaml file with the provided content

# Path to the win32_event_log.d/conf.yaml file
Write-Host "Updating win32_event_log.d/conf.yaml file"
$windowsEventLogConfigFile = "C:\ProgramData\Datadog\conf.d\win32_event_log.d\conf.yaml"

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

# Create a new log configuration to collect all logs from every directory
$logConfigDirectory = "C:\ProgramData\Datadog\conf.d"
$logsConfig = "logs:"
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match "^[A-Z]:\\" }

foreach ($drive in $drives) {
    $driveLetter = $drive.Root
    $logsConfig += @"
    
  - type: file
    path: "$driveLetter\**\\*.log"
    service: $serviceName
    source: $sourceName
    env: $environmentName
  - type: file
    path: "$driveLetter\**\\*\\*.log"
    service: $serviceName
    source: $sourceName
    env: $environmentName
  - type: file
    path: "$driveLetter\**\\*\\*\\*.log"
    service: $serviceName
    source: $sourceName
    env: $environmentName
  - type: file
    path: "$driveLetter\**\\*\\*\\*\\*.log"
    service: $serviceName
    source: $sourceName
    env: $environmentName
  - type: file
    path: "$driveLetter\**\\*\\*\\*\\*\\*.log"
    service: $serviceName
    source: $sourceName
    env: $environmentName
"@
}


# Create log configuration directory if it doesn't exist
if (-not (Test-Path $logConfigDirectory)) {
    New-Item -Path $logConfigDirectory -ItemType Directory
}

# Write the log configuration to a file
$logConfPath = "$logConfigDirectory\all_logs.d\conf.yaml"
New-Item -Path "$logConfigDirectory\all_logs.d" -ItemType Directory -Force
Set-Content -Path $logConfPath -Value $logsConfig

# Step 5: Restart the Datadog Agent Service
Write-Host "Restarting Datadog Agent Service"
& "$env:ProgramFiles\Datadog\Datadog Agent\bin\agent.exe" restart-service

# Wait for services to fully restart
Start-Sleep -Seconds 10  # Adjust the sleep time if necessary

& "$env:ProgramFiles\Datadog\Datadog Agent\bin\agent.exe" status
& "$env:ProgramFiles\Datadog\Datadog Agent\bin\agent.exe" launch-gui
`

      setGeneratedScript(script)
    }
  }

  const generateSingleCommand = () => {
    if (!generatedScript) return ''
    if (formData.os === 'linux') {
      return `sudo bash -c "cat << EOF > /tmp/datadog_install.sh
${generatedScript}
EOF
chmod +x /tmp/datadog_install.sh && /tmp/datadog_install.sh"`
    } else {
      return `powershell -Command "& {Set-Content -Path $env:TEMP\\datadog_install.ps1 -Value @'
${generatedScript}
'@; Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File $env:TEMP\\datadog_install.ps1' -Verb RunAs}"`
    }
  }

  const copyToClipboard = (ref: React.RefObject<HTMLTextAreaElement>) => {
    if (ref.current) {
      ref.current.select()
      document.execCommand('copy')
      // Optionally, you can show a tooltip or notification here to indicate successful copy
    }
  }

  const renderStep = () => {
    switch (step) {
      case 1:
        return (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold">Step 1: Select Operating System</h2>
            <RadioGroup
              value={formData.os}
              onValueChange={(value) => setFormData((prev) => ({ ...prev, os: value }))}
              className="flex flex-col space-y-2"
            >
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="linux" id="os-linux" />
                <Label htmlFor="os-linux">Linux</Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="windows" id="os-windows" />
                <Label htmlFor="os-windows">Windows</Label>
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
          </div>
        )
      case 3:
        return (
          <div className="space-y-4">
            <h2 className="text-xl font-semibold">Step 3: Enter API Key</h2>
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
          </div>
        )
      default:
        return (
          <div className="space-y-6">
            <h2 className="text-xl font-semibold">Additional Configuration</h2>
            <div>
              <Label htmlFor="serviceName">Service Name</Label>
              <Input type="text" id="serviceName" name="serviceName" value={formData.serviceName} onChange={handleInputChange} placeholder="Enter the service name" />
            </div>
            <div>
              <Label htmlFor="source">Source</Label>
              <Input type="text" id="source" name="source" value={formData.source} onChange={handleInputChange} placeholder="Enter the source" />
            </div>
            <div>
              <Label htmlFor="env">Environment</Label>
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
                  {formData.features.apm && formData.os === 'linux' && (
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
                          label="JavaScript"
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
                    docLink="https://docs.datadoghq.com/service_monitoring/"
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
                    label="OTLP"
                    checked={formData.features.otlp}
                    onCheckedChange={() => handleFeatureToggle('otlp')}
                    docLink="https://docs.datadoghq.com/opentelemetry/"
                  />
                </div>
              </div>
            </div>
            <div className="my-6 border-t border-gray-200"></div>
            <div className="space-y-2">
              <Label>Advanced Options</Label>
              <div className="flex items-center space-x-2">
                <Checkbox id="collectAllLogs" checked={formData.advancedOptions.collectAllLogs} onCheckedChange={() => handleAdvancedOptionToggle('collectAllLogs')} />
                <Label htmlFor="collectAllLogs">Collect All Logs</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox id="updateLogPermissions" checked={formData.advancedOptions.updateLogPermissions} onCheckedChange={() => handleAdvancedOptionToggle('updateLogPermissions')} />
                <Label htmlFor="updateLogPermissions">Update Log Permissions</Label>
              </div>
            </div>
          </div>
        )
    }
  }

  return (
    <div className="container mx-auto p-4 max-w-3xl">
      <h1 className="text-2xl font-bold mb-4">Enhanced Datadog Agent Installation Script Generator</h1>
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
            <Button type="button" onClick={generateScript}>
              Generate Script
            </Button>
          )}
        </div>
      </form>
      {generatedScript && (
        <div className="mt-8 relative">
          <h2 className="text-xl font-bold mb-2">Generated Installation Script</h2>
          <Button
            type="button"
            variant="outline"
            size="icon"
            className="absolute top-8 right-2 z-10"
            onClick={() => copyToClipboard(scriptRef)}
            aria-label="Copy generated script"
          >
            <Copy className="h-4 w-4" />
          </Button>
          <Textarea ref={scriptRef} value={generatedScript} readOnly className="h-96 font-mono text-sm pr-10" />
        </div>
      )}
      {generatedScript && (
        <div className="mt-8">
          <h2 className="text-xl font-bold mb-2">How to Execute the Script</h2>
          <h3 className="text-lg font-semibold mt-4 mb-2">Option 1: Single Command Execution</h3>
          <p>Copy and paste the following command into your terminal to create, make executable, and run the script:</p>
          <div className="relative mt-2">
            <Button
              type="button"
              variant="outline"
              size="icon"
              className="absolute top-2 right-2 z-10"
              onClick={() => copyToClipboard(singleCommandRef)}
              aria-label="Copy single command execution"
            >
              <Copy className="h-4 w-4" />
            </Button>
            <Textarea ref={singleCommandRef} value={generateSingleCommand()} readOnly className="h-24 font-mono text-sm pr-10" />
          </div>
          <p className="mt-2 text-sm text-muted-foreground">Note: This command will create the script, make it executable, and run it with appropriate privileges.</p>

          <h3 className="text-lg font-semibold mt-6 mb-2">Option 2: Step-by-Step Execution</h3>
          <ol className="list-decimal list-inside space-y-2">
            <li>Copy the generated script from the "Generated Installation Script" textarea above.</li>
            <li>Open a text editor on your {formData.os === 'linux' ? 'Linux' : 'Windows'} machine.</li>
            <li>Paste the copied script into the text editor.</li>
            <li>Save the file with a {formData.os === 'linux' ? '.sh' : '.ps1'} extension (e.g., {formData.os === 'linux' ? 'datadog_install.sh'  : 'datadog_install.ps1'}).</li>
            <li>Open a {formData.os === 'linux' ? 'terminal' : 'PowerShell window'} on your machine.</li>
            <li>Navigate to the directory where you saved the script using the cd command.</li>
            {formData.os === 'linux' ? (
              <>
                <li>Make the script executable by running the following command:
                  <pre className="bg-muted p-2 mt-1 rounded">chmod +x datadog_install.sh</pre>
                </li>
                <li>Execute the script with root privileges using sudo:
                  <pre className="bg-muted p-2 mt-1 rounded">sudo ./datadog_install.sh</pre>
                </li>
              </>
            ) : (
              <li>Execute the script with administrator privileges:
                <pre className="bg-muted p-2 mt-1 rounded">powershell -ExecutionPolicy Bypass -File .\datadog_install.ps1</pre>
              </li>
            )}
            <li>Follow any prompts or instructions provided by the script during execution.</li>
            <li>Once the script completes, verify that the Datadog Agent is running:
              <pre className="bg-muted p-2 mt-1 rounded">
                {formData.os === 'linux' ? 'sudo datadog-agent status' : '& "$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe" status'}
              </pre>
            </li>
          </ol>
          <p className="mt-4 text-red-600 font-semibold">
            Warning: Always review scripts before running them with elevated privileges. Ensure you trust the source and understand the actions the script will perform on your system.
          </p>
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
