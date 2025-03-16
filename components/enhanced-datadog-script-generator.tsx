'use client'

import { useState, useRef, useEffect } from 'react'
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { Checkbox } from "@/components/ui/checkbox"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Card, CardContent } from "@/components/ui/card"
import { Copy, ExternalLink, Server, Monitor, DockIcon as Docker, Cloud, CheckCircle2, AlertCircle, Terminal, FileCode, ChevronRight, ChevronLeft, Cpu, Network, Shield, Activity, Code } from 'lucide-react'

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
  const [copySuccess, setCopySuccess] = useState(false)
  const scriptRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    if (copySuccess) {
      const timer = setTimeout(() => {
        setCopySuccess(false)
      }, 2000)
      return () => clearTimeout(timer)
    }
  }, [copySuccess])

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
    echo "Restarting the Datadog Agent with... sudo systemctl restart datadog-agent"
elif command -v service >/dev/null; then
    sudo service datadog-agent restart
    echo "Restarting the Datadog Agent with... sudo service datadog-agent restart"
else
    echo "Could not determine how to restart the Datadog Agent. Please restart it manually."
fi

# Get Datadog Agent Status
sudo datadog-agent status

echo "Datadog Agent installation and configuration complete."

echo "Restart Datadig Agent with command... sudo systemctl restart datadog-agent or sudo service datadog-agent restart"
echo "Get Datadog Agent Status with command... sudo systemctl restart datadog-agent"
echo "PLEASE RESTART THE DATADOG AGENT AND YOUR APPLICATION SERVICE TO SEE DATA!"

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

Write-Host "Restart the Datadog Agent Service with... & "$env:ProgramFiles\Datadog\Datadog Agent\bin\agent.exe" restart-service"
Write-Host "Status of Datadog Agent Service with... & "$env:ProgramFiles\Datadog\Datadog Agent\bin\agent.exe" status"
Write-Host "GUI of Datadog Agent Service with... & "$env:ProgramFiles\Datadog\Datadog Agent\bin\agent.exe" launch-gui"
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
echo "You can view the logs by running: sudo docker logs dd-agent"
echo "You can view the status by running: sudo docker exec -it dd-agent agent status"
echo "PLEASE RESTART YOUR APPLICATION SERVICE CONTAINERS TO SEE APM DATA!"
`

      setGeneratedScript(script)
    }
  }

  const copyToClipboard = async () => {
    if (scriptRef.current) {
      try {
        await navigator.clipboard.writeText(scriptRef.current.value)
        setCopySuccess(true)
      } catch (err) {
        // Fallback for older browsers
        scriptRef.current.select()
        document.execCommand('copy')
        setCopySuccess(true)
      }
    }
  }

  const getPlatformIcon = (platform: string) => {
    switch (platform) {
      case 'linux':
        return <Server className="h-8 w-8 mb-2" />
      case 'windows':
        return <Monitor className="h-8 w-8 mb-2" />
      case 'docker':
        return <Docker className="h-8 w-8 mb-2" />
      case 'kubernetes':
        return <Cloud className="h-8 w-8 mb-2" />
      default:
        return null
    }
  }

  const renderStep = () => {
    switch (step) {
      case 1:
        return (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold">Select Platform</h2>
            <p className="text-gray-500">Choose the platform where you'll install the Datadog Agent</p>
            
            <div className="grid grid-cols-2 gap-4 mt-6">
              {['linux', 'windows', 'docker', 'kubernetes'].map((platform) => (
                <Card 
                  key={platform}
                  className={`cursor-pointer transition-all hover:shadow-md ${formData.os === platform ? 'border-primary ring-2 ring-primary/20' : 'hover:border-gray-300'}`}
                  onClick={() => setFormData((prev) => ({ ...prev, os: platform }))}
                >
                  <CardContent className="flex flex-col items-center justify-center p-6">
                    {getPlatformIcon(platform)}
                    <h3 className="text-lg font-medium capitalize">{platform}</h3>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )
        case 2:
            return (
              <div className="space-y-6">
                <h2 className="text-2xl font-semibold">Select Datadog Site</h2>
                <p className="text-gray-500">Choose the Datadog site that corresponds to your account</p>
                
                <div className="mt-4">
                  <Select value={formData.site} onValueChange={(value) => setFormData((prev) => ({ ...prev, site: value }))}>
                    <SelectTrigger className="w-full">
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
                
                {formData.os === 'kubernetes' && formData.site && (
                  <div className="mt-6 p-6 border rounded-lg bg-blue-50 shadow-sm">
                    <div className="flex items-start">
                      <div className="flex-shrink-0 mt-1">
                        <AlertCircle className="h-5 w-5 text-blue-600" />
                      </div>
                      <div className="ml-3">
                        <h3 className="text-lg font-medium text-blue-800 mb-2">Kubernetes Installation</h3>
                        <p className="text-blue-700 mb-2">For Kubernetes installation, you'll be redirected to the official Datadog documentation with your selected site.</p>
                        <p className="text-blue-700 mb-3">After clicking "Next", you'll be taken to:</p>
                        <a 
                          href={getKubernetesUrl()} 
                          target="_blank" 
                          rel="noopener noreferrer" 
                          className="flex items-center text-blue-600 hover:text-blue-800 hover:underline font-medium"
                        >
                          {getKubernetesUrl()}
                          <ExternalLink className="ml-1 h-4 w-4" />
                        </a>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )
          case 3:
            return (
              <div className="space-y-6">
                <h2 className="text-2xl font-semibold">Enter API Key</h2>
                {formData.os === 'kubernetes' ? (
                  <div className="p-6 border rounded-lg bg-blue-50 shadow-sm">
                    <div className="flex items-start">
                      <div className="flex-shrink-0 mt-1">
                        <AlertCircle className="h-5 w-5 text-blue-600" />
                      </div>
                      <div className="ml-3">
                        <h3 className="text-lg font-medium text-blue-800 mb-2">Kubernetes Installation</h3>
                        <p className="text-blue-700 mb-3">Please follow the instructions on the Datadog website that opened in a new tab.</p>
                        <p className="text-blue-700 mb-3">If you need to access the page again, you can visit:</p>
                        <a 
                          href={getKubernetesUrl()} 
                          target="_blank" 
                          rel="noopener noreferrer" 
                          className="flex items-center text-blue-600 hover:text-blue-800 hover:underline font-medium mb-4"
                        >
                          {getKubernetesUrl()}
                          <ExternalLink className="ml-1 h-4 w-4" />
                        </a>
                        <Button 
                          type="button" 
                          className="mt-2 flex items-center" 
                          onClick={() => window.open(getKubernetesUrl(), '_blank')}
                        >
                          <ExternalLink className="mr-2 h-4 w-4" />
                          Open Kubernetes Installation Guide
                        </Button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <p className="text-gray-500">Enter your Datadog API key to authenticate the agent</p>
                    <div className="space-y-2">
                      <Label htmlFor="apiKey" className="text-sm font-medium">API Key</Label>
                      <div className="relative">
                        <Input
                          type="text"
                          id="apiKey"
                          name="apiKey"
                          value={formData.apiKey}
                          onChange={handleInputChange}
                          placeholder="Enter your Datadog API key"
                          className="pr-10"
                        />
                        <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                          <FileCode className="h-4 w-4 text-gray-400" />
                        </div>
                      </div>
                      <p className="text-xs text-gray-500">
                        You can find your API key in the <a href={`https://${formData.site || 'app.datadoghq.com'}/organization-settings/api-keys`} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Datadog API Keys</a> section.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )
          default:
            return (
              <div className="space-y-6">
                {formData.os === 'kubernetes' ? (
                  <div className="p-6 border rounded-lg bg-blue-50 shadow-sm">
                    <div className="flex items-start">
                      <div className="flex-shrink-0 mt-1">
                        <AlertCircle className="h-5 w-5 text-blue-600" />
                      </div>
                      <div className="ml-3">
                        <h3 className="text-lg font-medium text-blue-800 mb-2">Kubernetes Installation</h3>
                        <p className="text-blue-700 mb-3">Please follow the instructions on the Datadog website that opened in a new tab.</p>
                        <p className="text-blue-700 mb-3">If you need to access the page again, you can visit:</p>
                        <a 
                          href={getKubernetesUrl()} 
                          target="_blank" 
                          rel="noopener noreferrer" 
                          className="flex items-center text-blue-600 hover:text-blue-800 hover:underline font-medium mb-4"
                        >
                          {getKubernetesUrl()}
                          <ExternalLink className="ml-1 h-4 w-4" />
                        </a>
                        <Button 
                          type="button" 
                          className="mt-2 flex items-center" 
                          onClick={() => window.open(getKubernetesUrl(), '_blank')}
                        >
                          <ExternalLink className="mr-2 h-4 w-4" />
                          Open Kubernetes Installation Guide
                        </Button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <>
                    <h2 className="text-2xl font-semibold">Additional Configuration</h2>
                    <div className="space-y-4">
                      <div>
                        <Label htmlFor="env" className="text-sm font-medium">Environment Name</Label>
                        <div className="relative mt-1">
                          <Input 
                            type="text" 
                            id="env" 
                            name="env" 
                            value={formData.env} 
                            onChange={handleInputChange} 
                            placeholder="e.g., production, staging, development"
                            className="pr-10"
                          />
                          <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                            <Code className="h-4 w-4 text-gray-400" />
                          </div>
                        </div>
                        <p className="text-xs text-gray-500 mt-1">
                          This will be used to tag your metrics and logs
                        </p>
                      </div>
                      
                      <Card className="mt-6">
                        <CardContent className="p-6">
                          <h3 className="text-lg font-medium flex items-center mb-4">
                            <Activity className="h-5 w-5 mr-2 text-primary" />
                            Monitoring Features
                          </h3>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <FeatureCheckbox
                              id="logs"
                              label="Logs"
                              checked={formData.features.logs}
                              onCheckedChange={() => handleFeatureToggle('logs')}
                              docLink="https://docs.datadoghq.com/logs/"
                              icon={<FileCode className="h-4 w-4 text-gray-600" />}
                            />
                            <FeatureCheckbox
                              id="apm"
                              label="APM"
                              checked={formData.features.apm}
                              onCheckedChange={() => handleFeatureToggle('apm')}
                              docLink="https://docs.datadoghq.com/tracing/"
                              icon={<Activity className="h-4 w-4 text-gray-600" />}
                            />
                            {formData.features.apm && formData.os === 'linux' && (
                              <div className="col-span-1 md:col-span-2 ml-6 mt-2 p-3 bg-gray-50 rounded-md border">
                                <Label className="text-sm font-medium mb-2 block">APM Instrumentation Languages</Label>
                                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                                  <FeatureCheckbox
                                    id="apm-java"
                                    label="Java"
                                    checked={formData.apmInstrumentationLanguages.java}
                                    onCheckedChange={() => handleApmLanguageToggle('java')}
                                    docLink="https://docs.datadoghq.com/tracing/setup_overview/setup/java/"
                                    icon={<Code className="h-4 w-4 text-gray-600" />}
                                  />
                                  <FeatureCheckbox
                                    id="apm-js"
                                    label="JavaScript"
                                    checked={formData.apmInstrumentationLanguages.js}
                                    onCheckedChange={() => handleApmLanguageToggle('js')}
                                    docLink="https://docs.datadoghq.com/tracing/setup_overview/setup/nodejs/"
                                    icon={<Code className="h-4 w-4 text-gray-600" />}
                                  />
                                  <FeatureCheckbox
                                    id="apm-python"
                                    label="Python"
                                    checked={formData.apmInstrumentationLanguages.python}
                                    onCheckedChange={() => handleApmLanguageToggle('python')}
                                    docLink="https://docs.datadoghq.com/tracing/setup_overview/setup/python/"
                                    icon={<Code className="h-4 w-4 text-gray-600" />}
                                  />
                                  <FeatureCheckbox
                                    id="apm-dotnet"
                                    label=".NET"
                                    checked={formData.apmInstrumentationLanguages.dotnet}
                                    onCheckedChange={() => handleApmLanguageToggle('dotnet')}
                                    docLink="https://docs.datadoghq.com/tracing/setup_overview/setup/dotnet/"
                                    icon={<Code className="h-4 w-4 text-gray-600" />}
                                  />
                                  <FeatureCheckbox
                                    id="apm-ruby"
                                    label="Ruby"
                                    checked={formData.apmInstrumentationLanguages.ruby}
                                    onCheckedChange={() => handleApmLanguageToggle('ruby')}
                                    docLink="https://docs.datadoghq.com/tracing/setup_overview/setup/ruby/"
                                    icon={<Code className="h-4 w-4 text-gray-600" />}
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
                              icon={<Cpu className="h-4 w-4 text-gray-600" />}
                            />
                            <FeatureCheckbox
                              id="networkMonitoring"
                              label="Network Monitoring"
                              checked={formData.features.networkMonitoring}
                              onCheckedChange={() => handleFeatureToggle('networkMonitoring')}
                              docLink="https://docs.datadoghq.com/network_monitoring/"
                              icon={<Network className="h-4 w-4 text-gray-600" />}
                            />
                            <FeatureCheckbox
                              id="universalServiceMonitoring"
                              label="Universal Service Monitoring"
                              checked={formData.features.universalServiceMonitoring}
                              onCheckedChange={() => handleFeatureToggle('universalServiceMonitoring')}
                              docLink="https://docs.datadoghq.com/service_monitoring/"
                              icon={<Activity className="h-4 w-4 text-gray-600" />}
                            />
                          </div>
                        </CardContent>
                      </Card>
    
                      <Card className="mt-4">
                        <CardContent className="p-6">
                          <h3 className="text-lg font-medium flex items-center mb-4">
                            <Shield className="h-5 w-5 mr-2 text-primary" />
                            Security Features
                          </h3>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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
                              icon={<Cloud className="h-4 w-4 text-gray-600" />}
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
                              icon={<Shield className="h-4 w-4 text-gray-600" />}
                            />
                          </div>
                        </CardContent>
                      </Card>
    
                      <Card className="mt-4">
                        <CardContent className="p-6">
                          <h3 className="text-lg font-medium flex items-center mb-4">
                            <Code className="h-5 w-5 mr-2 text-primary" />
                            Other Features
                          </h3>
                          <div className="grid grid-cols-1 gap-3">
                            <FeatureCheckbox
                              id="otlp"
                              label="OpenTelemetry Protocol (OTLP)"
                              checked={formData.features.otlp}
                              onCheckedChange={() => handleFeatureToggle('otlp')}
                              docLink="https://docs.datadoghq.com/opentelemetry/"
                              icon={<Code className="h-4 w-4 text-gray-600" />}
                            />
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                    
                    {formData.os !== 'docker' && (
                      <Card className="mt-6">
                        <CardContent className="p-6">
                          <h3 className="text-lg font-medium flex items-center mb-4">
                            <Terminal className="h-5 w-5 mr-2 text-primary" />
                            Advanced Options
                          </h3>
                          <div className="space-y-3">
                            {formData.os === 'linux' && (
                              <>
                                <div className="flex items-center space-x-2 p-2 hover:bg-gray-50 rounded-md">
                                  <Checkbox 
                                    id="collectAllLogs" 
                                    checked={formData.advancedOptions.collectAllLogs} 
                                    onCheckedChange={() => handleAdvancedOptionToggle('collectAllLogs')} 
                                  />
                                  <Label htmlFor="collectAllLogs" className="cursor-pointer">Collect All Logs</Label>
                                </div>
                                <div className="flex items-center space-x-2 p-2 hover:bg-gray-50 rounded-md">
                                  <Checkbox 
                                    id="updateLogPermissions" 
                                    checked={formData.advancedOptions.updateLogPermissions} 
                                    onCheckedChange={() => handleAdvancedOptionToggle('updateLogPermissions')} 
                                  />
                                  <Label htmlFor="updateLogPermissions" className="cursor-pointer">Update Log Permissions</Label>
                                </div>
                              </>
                            )}
                            {formData.os === 'windows' && (
                              <>
                                <div className="flex items-center space-x-2 p-2 hover:bg-gray-50 rounded-md">
                                  <Checkbox 
                                    id="collectIISLogs" 
                                    checked={formData.advancedOptions.collectIISLogs} 
                                    onCheckedChange={() => handleAdvancedOptionToggle('collectIISLogs')} 
                                  />
                                  <Label htmlFor="collectIISLogs" className="cursor-pointer">Collect IIS Logs</Label>
                                </div>
                                <div className="flex items-center space-x-2 p-2 hover:bg-gray-50 rounded-md">
                                  <Checkbox 
                                    id="collectWindowsEventLogs" 
                                    checked={formData.advancedOptions.collectWindowsEventLogs} 
                                    onCheckedChange={() => handleAdvancedOptionToggle('collectWindowsEventLogs')} 
                                  />
                                  <Label htmlFor="collectWindowsEventLogs" className="cursor-pointer">Collect Windows Event Logs</Label>
                                </div>
                              </>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    )}
                  </>
                )}
              </div>
            )
        }
      }
    
      return (
        <div className="container mx-auto p-4 max-w-4xl">
          <Card className="border-0 shadow-lg">
            <CardContent className="p-6 md:p-8">
              <h1 className="text-3xl font-bold mb-6 text-center">Datadog Agent Installation Script Generator</h1>
              
              <div className="mb-8">
                <div className="flex items-center justify-center">
                  {[1,2,3,4].map((s) => (
                    <div key={s} className="flex items-center">
                      <div 
                        className={`w-10 h-10 rounded-full flex items-center justify-center transition-all ${
                          s === step 
                            ? 'bg-primary text-primary-foreground shadow-md' 
                            : s < step 
                              ? 'bg-primary/20 text-primary' 
                              : 'bg-muted text-muted-foreground'
                        }`}
                      >
                        {s < step ? <CheckCircle2 className="h-5 w-5" /> : s}
                      </div>
                      {s < 4 && (
                        <div 
                          className={`h-1 w-12 ${
                            s < step 
                              ? 'bg-primary' 
                              : 'bg-muted'
                          }`} 
                        />
                      )}
                    </div>
                  ))}
                </div>
                <div className="flex justify-between mt-2 text-sm text-gray-500">
                  <span>Platform</span>
                  <span>Site</span>
                  <span>API Key</span>
                  <span>Configure</span>
                </div>
              </div>
              
              <form className="space-y-6">
                {renderStep()}
                
                <div className="flex justify-between mt-8">
                  {step > 1 && (
                    <Button 
                      type="button" 
                      variant="outline" 
                      onClick={prevStep}
                      className="flex items-center"
                    >
                      <ChevronLeft className="mr-1 h-4 w-4" />
                      Previous
                    </Button>
                  )}
                  <div className="flex-1"></div>
                  {step < 4 ? (
                    <Button 
                      type="button" 
                      onClick={nextStep}
                      className="flex items-center"
                    >
                      Next
                      <ChevronRight className="ml-1 h-4 w-4" />
                    </Button>
                  ) : (
                    <Button 
                      type="button" 
                      onClick={generateScript}
                      disabled={formData.os === 'kubernetes'}
                      className="flex items-center"
                    >
                      <FileCode className="mr-2 h-4 w-4" />
                      Generate Script
                    </Button>
                  )}
                </div>
              </form>
            </CardContent>
          </Card>
          
          {generatedScript && formData.os !== 'kubernetes' && (
            <Card className="mt-8 border-0 shadow-lg overflow-hidden">
              <CardContent className="p-0">
                <div className="p-4 md:p-6 bg-gray-50 border-b flex justify-between items-center">
                  <h2 className="text-xl font-bold">Generated Installation Script</h2>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={copyToClipboard}
                    className="flex items-center"
                    disabled={copySuccess}
                  >
                    {copySuccess ? (
                      <>
                        <CheckCircle2 className="mr-1 h-4 w-4 text-green-500" />
                        Copied!
                      </>
                    ) : (
                      <>
                        <Copy className="mr-1 h-4 w-4" />
                        Copy
                      </>
                    )}
                  </Button>
                </div>
                <div className="relative">
                  <Textarea 
                    ref={scriptRef} 
                    value={generatedScript} 
                    readOnly 
                    className="h-96 font-mono text-sm p-4 border-0 focus-visible:ring-0 resize-none" 
                  />
                </div>
              </CardContent>
            </Card>
          )}
          
          {generatedScript && formData.os !== 'kubernetes' && (
            <Card className="mt-8 border-0 shadow-lg">
              <CardContent className="p-6 md:p-8">
                <h2 className="text-2xl font-bold mb-4">How to Execute the Script</h2>
                <ol className="list-decimal list-inside space-y-4 ml-2">
                  <li className="text-gray-800">
                    Copy the generated script from above.
                    <div className="ml-6 mt-2">
                      <Button 
                        type="button" 
                        variant="outline" 
                        size="sm" 
                        onClick={copyToClipboard}
                        className="flex items-center"
                      >
                        <Copy className="mr-1 h-4 w-4" />
                        Copy Script
                      </Button>
                    </div>
                  </li>
                  
                  {formData.os === 'docker' ? (
                    <>
                      <li className="text-gray-800">Open a terminal on your Docker host machine.</li>
                      <li className="text-gray-800">
                        Paste the copied script into a new file, for example, <code className="bg-gray-100 px-1 py-0.5 rounded text-sm">datadog_install.sh</code>.
                      </li>
                      <li className="text-gray-800">
                        Make the script executable:
                        <pre className="bg-gray-100 p-3 mt-2 rounded-md text-sm overflow-x-auto">chmod +x datadog_install.sh</pre>
                      </li>
                      <li className="text-gray-800">
                        Execute the script with:
                        <pre className="bg-gray-100 p-3 mt-2 rounded-md text-sm overflow-x-auto">sudo ./datadog_install.sh</pre>
                      </li>
                    </>
                  ) : (
                    <>
                      <li className="text-gray-800">Open a text editor on your {formData.os === 'linux' ? 'Linux' : 'Windows'} machine.</li>
                      <li className="text-gray-800">
                        Paste the copied script into the text editor and save it with a {formData.os === 'linux' ? '.sh' : '.ps1'} extension (e.g., {formData.os === 'linux' ? 'datadog_install.sh'  : 'datadog_install.ps1'}).
                      </li>
                      <li className="text-gray-800">
                        Open a {formData.os === 'linux' ? 'terminal' : 'PowerShell window'} on your machine.
                      </li>
                      <li className="text-gray-800">
                        Navigate to the directory where you saved the script using the cd command.
                      </li>
                      {formData.os === 'linux' ? (
                        <>
                          <li className="text-gray-800">
                            Make the script executable:
                            <pre className="bg-gray-100 p-3 mt-2 rounded-md text-sm overflow-x-auto">chmod +x datadog_install.sh</pre>
                          </li>
                          <li className="text-gray-800">
                            Execute the script with root privileges:
                            <pre className="bg-gray-100 p-3 mt-2 rounded-md text-sm overflow-x-auto">sudo ./datadog_install.sh</pre>
                          </li>
                        </>
                      ) : (
                        <li className="text-gray-800">
                          Execute the script with administrator privileges:
                          <pre className="bg-gray-100 p-3 mt-2 rounded-md text-sm overflow-x-auto">powershell -ExecutionPolicy Bypass -File .\datadog_install.ps1</pre>
                        </li>
                      )}
                    </>
                  )}
                  <li className="text-gray-800">Follow any prompts or instructions provided by the script during execution.</li>
                  <li className="text-gray-800">
                    Once the script completes, verify that the Datadog Agent is running:
                    <pre className="bg-gray-100 p-3 mt-2 rounded-md text-sm overflow-x-auto">
                      {formData.os === 'linux' ? 'sudo datadog-agent status' : formData.os === 'windows' ? '& "$env:ProgramFiles\\Datadog\\Datadog Agent\\bin\\agent.exe" status' : 'sudo docker exec -it dd-agent agent status'}
                    </pre>
                  </li>
                </ol>
                
                <div className="mt-6 p-4 border border-red-200 bg-red-50 rounded-md flex items-start">
                  <AlertCircle className="h-5 w-5 text-red-500 mt-0.5 flex-shrink-0" />
                  <p className="ml-3 text-red-700 text-sm">
                    <strong>Warning:</strong> Always review scripts before running them with elevated privileges. Ensure you trust the source and understand the actions the script will perform on your system.
                  </p>
                </div>
                
                {formData.os === 'docker' && (
                  <div className="mt-8">
                    <h3 className="text-xl font-bold mb-4">Run on Docker Compose</h3>
                    <p className="mb-4 text-gray-700">
                      If you prefer to use Docker Compose to manage your containers, you can easily convert the Docker run command to a Docker Compose file:
                    </p>
                    <ol className="list-decimal list-inside space-y-3 ml-2">
                      <li className="text-gray-800">Copy the entire Docker run command from the generated script.</li>
                      <li className="text-gray-800">
                        Visit <a href="https://www.composerize.com/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline font-medium">composerize.com</a>.
                      </li>
                      <li className="text-gray-800">Paste the Docker run command into the input field on the Composerize website.</li>
                      <li className="text-gray-800">Composerize will automatically convert the command into a Docker Compose YAML format.</li>
                      <li className="text-gray-800">Copy the generated Docker Compose YAML.</li>
                      <li className="text-gray-800">
                        Create a new file named <code className="bg-gray-100 px-1 py-0.5 rounded text-sm">docker-compose.yml</code> on your Docker host machine and paste the YAML content into it.
                      </li>
                      <li className="text-gray-800">
                        Run the Datadog Agent using Docker Compose:
                        <pre className="bg-gray-100 p-3 mt-2 rounded-md text-sm overflow-x-auto">docker-compose up -d</pre>
                      </li>
                    </ol>
                    <p className="mt-4 text-gray-700">
                      Using Docker Compose can make it easier to manage and update your Datadog Agent configuration, especially if you're running multiple containers or services.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
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
      icon?: React.ReactNode
    }
    
    function FeatureCheckbox({ id, label, checked, onCheckedChange, docLink, icon }: FeatureCheckboxProps) {
      return (
        <div className="flex items-center space-x-2 p-2 hover:bg-gray-50 rounded-md transition-colors">
          <Checkbox id={id} checked={checked} onCheckedChange={onCheckedChange} />
          <div className="flex items-center flex-1">
            {icon && <span className="mr-2">{icon}</span>}
            <Label htmlFor={id} className="cursor-pointer">{label}</Label>
          </div>
          <a 
            href={docLink} 
            target="_blank" 
            rel="noopener noreferrer" 
            className="text-primary hover:text-primary/80 ml-auto"
            title="View documentation"
          >
            <ExternalLink className="h-4 w-4" />
          </a>
        </div>
      )
    }
