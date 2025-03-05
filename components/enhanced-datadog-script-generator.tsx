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
    },
    advancedOptions: {
      collectAllLogs: true,
      updateLogPermissions: true,
      collectIISLogs: true,
      collectWindowsEventLogs: true,
    },
  })

  const [generatedScript, setGeneratedScript] = useState('')
  const scriptRef = useRef<HTMLTextAreaElement>(null)

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
      alert("Please select a platform.")
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

      const script = `

#!/bin/bash
#!/bin/bash
#!/bin/bash
# This is an unofficial Datadog Agent Installation Script
# This is not affiliated with Datadog, please reach out to your Datadog account manager if you have any issues.
#!/bin/bash

set -x

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Please run this script as root or with sudo."
   exit 1
fi

# Datadog site and API key
export DD_SITE="${formData.site}"
export DD_API_KEY="${formData.apiKey}"

# Environment
export ENV_NAME="${formData.env}"

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
mkdir -p /etc/datadog-agent/conf.d/all_logs.d

log_dirs=$(find /var/log -type f -name "*.log" 2>/dev/null | xargs -r dirname | sort -u)

# Begin the logs configuration file
echo "logs:" > /etc/datadog-agent/conf.d/all_logs.d/conf.yaml

# Loop through each directory and create a log config entry
while IFS= read -r dir; do
    # Derive a service name from the directory name
    # For example, use the last component of the directory path as the service name.
    service_name=$(basename "$dir")
    source_name=$(basename "$dir")

    # Create a log collection configuration entry for this directory
    cat <<EOF >> /etc/datadog-agent/conf.d/all_logs.d/conf.yaml
  - type: file
    path: "$dir/*.log"
    service: "$service_name"
    source: "$source_name"
EOF

done <<< "$log_dirs"` : ''}

${formData.advancedOptions.updateLogPermissions ? `# Update permissions for .log files
echo "Updating permissions for .log files..."
find / -type f -name "*.log" 2>/dev/null | while read -r logfile; do
    chmod o+rx "$logfile"
done
sudo chmod -R o+r /var/log` : ''}

# Restart the Datadog Agent to apply changes
echo "Restarting the Datadog Agent..."
if command -v systemctl >/dev/null; then
    sudo systemctl restart datadog-agent
elif command -v service >/dev/null; then
    sudo service datadog-agent restart
else
    echo "Could not determine how to restart the Datadog Agent. Please restart it manually."
fi

# Get Datadog Agent Status
sudo datadog-agent status

echo "Datadog Agent installation and configuration complete."
`

      setGeneratedScript(script)
    } else if (formData.os === 'windows') {
      const script = `
# Prompt for Datadog site selection
$ddSite = "${formData.site}"

# Prompt for Datadog API key
$apiKey = "${formData.apiKey}"

# Prompt for Environment Name
$environmentName = "${formData.env}"

# Construct tags from input
$tags = "env:$environmentName"

# Step 3: Install the Datadog Agent
Write-Host "Installing Datadog Agent"
Start-Process -Wait msiexec -ArgumentList '/passive /i "https://s3.amazonaws.com/ddagent-windows-stable/datadog-agent-7-latest.amd64.msi" APIKEY="$apiKey" SITE="$ddSite" TAGS="$tags"'

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
  enabled: ${formData.features.apm}

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
# Step 5: Restart the Datadog Agent Service
Write-Host "Restarting Datadog Agent Service"
& "$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe" restart-service

# Wait for services to fully restart
Start-Sleep -Seconds 10  # Adjust the sleep time if necessary

& "$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe" status
& "$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe" launch-gui
`

      setGeneratedScript(script)
    } else if (formData.os === 'docker') {
      const script = `# Run the Datadog Agent installation script for Docker
${formData.features.apm ? 'DD_APM_INSTRUMENTATION_ENABLED=docker DD_NO_AGENT_INSTALL=true bash -c "$(curl -L https://install.datadoghq.com/scripts/install_script_docker_injection.sh)"' : ''}

# Run the Datadog Agent Docker container
docker run -d --name dd-agent \\
--cgroupns host \\
--pid host \\
-e DD_API_KEY=${formData.apiKey} \\
-e DD_SITE="${formData.site}" \\
-e DD_ENV=${formData.env} \\
-e DD_APM_ENABLED=${formData.features.apm} \\
${formData.features.apm ? '-e DD_APM_NON_LOCAL_TRAFFIC=true \\' : ''}
${formData.features.apm ? '-e DD_APM_RECEIVER_SOCKET=/opt/datadog/apm/inject/run/apm.socket \\' : ''}
${formData.features.apm ? '-e DD_DOGSTATSD_SOCKET=/opt/datadog/apm/inject/run/dsd.socket \\' : ''}
${formData.features.apm ? '-v /opt/datadog/apm:/opt/datadog/apm \\' : ''}
-e DD_APPSEC_ENABLED=${formData.features.threatProtection} \\
-e DD_IAST_ENABLED=${formData.features.codeSecurityProfiling} \\
-e DD_APPSEC_SCA_ENABLED=${formData.features.softwareCompositionAnalysis} \\
${formData.features.otlp ? `-e DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT=0.0.0.0:4317 \\
-e DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_HTTP_ENDPOINT=0.0.0.0:4318 \\
-e DD_OTLP_CONFIG_LOGS_ENABLED=true \\` : ''}
-e DD_LOGS_ENABLED=${formData.features.logs} \\
-e DD_LOGS_CONFIG_CONTAINER_COLLECT_ALL=${formData.features.logs} \\
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
-v /sys/kernel/debug:/sys/kernel/debug \\
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
echo "You can view the logs by running: docker logs dd-agent"
`

      setGeneratedScript(script)
    }
  }

  const copyToClipboard = async (text: string) => {
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
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="docker" id="os-docker" />
                <Label htmlFor="os-docker">Docker</Label>
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
              <Label htmlFor="env">Environment Name (eg: prod, stg, dev)</Label>
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
            onClick={() => copyToClipboard(generatedScript)}
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
          <ol className="list-decimal list-inside space-y-2">
            <li>Copy the generated script from the "Generated Installation Script" textarea above.</li>
            {formData.os === 'docker' ? (
              <>
                <li>Open a terminal on your Docker host machine.</li>
                <li>Paste the copied script into a new file, for example, <code>datadog_install.sh</code>.</li>
                <li>Make the script executable by running: <pre className="bg-muted p-2 mt-1 rounded">chmod +x datadog_install.sh</pre></li>
                <li>Execute the script with: <pre className="bg-muted p-2 mt-1 rounded">sudo ./datadog_install.sh</pre></li>
              </>
            ) : (
              <>
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
