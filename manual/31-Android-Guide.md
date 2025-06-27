# 31. Android Guide

![ZehraSec](https://img.shields.io/badge/🛡️-ZehraSec%20Android-green?style=for-the-badge&logo=android)

**Version 3.0.0** | **Updated: June 19, 2025**

---

## 📱 **Overview**

This comprehensive guide covers the deployment, configuration, and management of ZehraSec Advanced Firewall on Android devices and systems. It includes support for Android smartphones, tablets, Android TV, and enterprise Android deployments.

---

## 📋 **System Requirements**

### **Minimum Requirements**
- **OS**: Android 8.0 (API level 26) or higher
- **RAM**: 2 GB (4 GB recommended)
- **Storage**: 1 GB available space
- **Network**: Wi-Fi or mobile data connection
- **Privileges**: Root access (for advanced features)

### **Recommended Requirements**
- **OS**: Android 12.0 (API level 31) or higher
- **RAM**: 4 GB (8 GB for enterprise)
- **Storage**: 4 GB available space
- **Network**: Wi-Fi 6 or 5G connectivity
- **Additional**: Hardware security module (HSM) support

### **Supported Android Versions**
- **Android 8.0 - 8.1**: Oreo (API 26-27)
- **Android 9**: Pie (API 28)
- **Android 10**: Q (API 29)
- **Android 11**: R (API 30)
- **Android 12-12L**: S (API 31-32)
- **Android 13**: Tiramisu (API 33)
- **Android 14**: UpsideDownCake (API 34)

### **Device Categories**
- **Smartphones**: All major manufacturers
- **Tablets**: 10" and larger screens
- **Android TV**: Set-top boxes and smart TVs
- **Android Auto**: Automotive systems
- **Wear OS**: Smartwatches (limited functionality)
- **Enterprise**: MDM-managed devices

---

## 🚀 **Installation**

### **Method 1: Google Play Store (Recommended)**

1. **Open Google Play Store**
   - Search for "ZehraSec Advanced Firewall"
   - Or visit: `https://play.google.com/store/apps/details?id=com.zehrasec.firewall`

2. **Install Application**
   ```
   Tap "Install" → Accept permissions → Wait for installation
   ```

3. **Launch Application**
   - Open ZehraSec from app drawer
   - Complete initial setup wizard
   - Grant required permissions

### **Method 2: APK Installation**

1. **Enable Unknown Sources**
   ```
   Settings → Security → Unknown Sources → Enable
   ```

2. **Download APK**
   ```bash
   # Download from official repository
   wget https://releases.zehrasec.com/android/zehrasec-advanced-firewall.apk
   
   # Transfer to device
   adb push zehrasec-advanced-firewall.apk /sdcard/Download/
   ```

3. **Install APK**
   ```bash
   # Via ADB
   adb install zehrasec-advanced-firewall.apk
   
   # Or manually on device
   # File Manager → Downloads → zehrasec-advanced-firewall.apk → Install
   ```

### **Method 3: Enterprise Deployment**

#### **Android Enterprise (Work Profile)**
```bash
# Deploy via MDM (Intune, VMware Workspace ONE, etc.)
# Upload APK to MDM console
# Create deployment policy
# Assign to device groups
```

#### **Managed Google Play**
```bash
# Add to private managed Google Play
# Configure app policies
# Deploy to managed devices
```

---

## ⚙️ **Configuration**

### **Initial Setup**

1. **First Launch Configuration**
   ```kotlin
   // Initialize ZehraSec on first launch
   class FirstLaunchSetup : Activity() {
       override fun onCreate(savedInstanceState: Bundle?) {
           super.onCreate(savedInstanceState)
           
           // Check for required permissions
           requestPermissions()
           
           // Initialize firewall engine
           initializeFirewall()
           
           // Configure default policies
           setupDefaultPolicies()
       }
       
       private fun requestPermissions() {
           val permissions = arrayOf(
               Manifest.permission.INTERNET,
               Manifest.permission.ACCESS_NETWORK_STATE,
               Manifest.permission.ACCESS_WIFI_STATE,
               Manifest.permission.WRITE_EXTERNAL_STORAGE,
               Manifest.permission.READ_PHONE_STATE,
               Manifest.permission.RECEIVE_BOOT_COMPLETED
           )
           
           ActivityCompat.requestPermissions(this, permissions, 1001)
       }
   }
   ```

2. **Network Permissions**
   ```xml
   <!-- AndroidManifest.xml -->
   <uses-permission android:name="android.permission.INTERNET" />
   <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
   <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
   <uses-permission android:name="android.permission.CHANGE_WIFI_STATE" />
   <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
   <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
   <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
   <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
   <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
   <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
   <uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" />
   ```

### **VPN Configuration**

ZehraSec Android uses VPN Service for network traffic interception:

```kotlin
// VPN Service Implementation
class ZehraSecVpnService : VpnService() {
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return if (intent?.action == ACTION_CONNECT) {
            connect()
            START_STICKY
        } else {
            disconnect()
            START_NOT_STICKY
        }
    }
    
    private fun connect() {
        val builder = Builder()
            .setSession("ZehraSec VPN")
            .addAddress("10.0.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("8.8.4.4")
            .setMtu(1500)
            .setBlocking(false)
        
        // Set up allowed/disallowed apps
        try {
            builder.addAllowedApplication("com.android.chrome")
            builder.addAllowedApplication("com.google.android.apps.messaging")
            // Add more allowed apps
        } catch (e: PackageManager.NameNotFoundException) {
            Log.e("ZehraSec", "Package not found: ${e.message}")
        }
        
        val vpnInterface = builder.establish()
        
        if (vpnInterface != null) {
            // Start packet processing
            startPacketProcessing(vpnInterface)
        }
    }
    
    private fun startPacketProcessing(vpnInterface: ParcelFileDescriptor) {
        Thread {
            val inputStream = FileInputStream(vpnInterface.fileDescriptor)
            val outputStream = FileOutputStream(vpnInterface.fileDescriptor)
            
            val buffer = ByteArray(32767)
            
            while (true) {
                try {
                    val length = inputStream.read(buffer)
                    if (length > 0) {
                        // Process packet through ZehraSec engine
                        val processedPacket = processPacket(buffer, length)
                        if (processedPacket != null) {
                            outputStream.write(processedPacket)
                        }
                    }
                } catch (e: IOException) {
                    Log.e("ZehraSec", "VPN connection error: ${e.message}")
                    break
                }
            }
        }.start()
    }
    
    private fun processPacket(buffer: ByteArray, length: Int): ByteArray? {
        // Implement packet processing logic
        // Parse IP packet, apply firewall rules, log if needed
        return buffer.copyOf(length)
    }
}
```

### **Device Administration**

For enterprise deployments, ZehraSec can be configured as a Device Administrator:

```kotlin
// Device Admin Receiver
class ZehraSecDeviceAdminReceiver : DeviceAdminReceiver() {
    
    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        // Device admin enabled
        Log.i("ZehraSec", "Device admin enabled")
    }
    
    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
        // Device admin disabled
        Log.i("ZehraSec", "Device admin disabled")
    }
    
    override fun onPasswordChanged(context: Context, intent: Intent, user: UserHandle) {
        super.onPasswordChanged(context, intent, user)
        // Password changed
        Log.i("ZehraSec", "Password changed")
    }
}
```

---

## 🔧 **Android-Specific Features**

### **Network Monitoring**

```kotlin
// Network Monitoring Service
class NetworkMonitoringService : Service() {
    
    private val connectivityManager by lazy {
        getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    }
    
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            super.onAvailable(network)
            Log.i("ZehraSec", "Network available: $network")
            
            // Get network capabilities
            val capabilities = connectivityManager.getNetworkCapabilities(network)
            when {
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> {
                    handleWifiConnection(network)
                }
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> {
                    handleCellularConnection(network)
                }
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> {
                    handleEthernetConnection(network)
                }
            }
        }
        
        override fun onLost(network: Network) {
            super.onLost(network)
            Log.i("ZehraSec", "Network lost: $network")
            handleNetworkLoss(network)
        }
        
        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            super.onCapabilitiesChanged(network, networkCapabilities)
            Log.i("ZehraSec", "Network capabilities changed: $network")
        }
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startNetworkMonitoring()
        return START_STICKY
    }
    
    private fun startNetworkMonitoring() {
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
            .build()
        
        connectivityManager.registerNetworkCallback(request, networkCallback)
    }
    
    private fun handleWifiConnection(network: Network) {
        // Handle Wi-Fi specific logic
        val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val wifiInfo = wifiManager.connectionInfo
        
        Log.i("ZehraSec", "Connected to Wi-Fi: ${wifiInfo.ssid}")
        
        // Apply Wi-Fi specific firewall rules
        applyWifiFirewallRules(wifiInfo)
    }
    
    private fun handleCellularConnection(network: Network) {
        // Handle cellular specific logic
        val telephonyManager = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        val networkOperator = telephonyManager.networkOperatorName
        
        Log.i("ZehraSec", "Connected to cellular: $networkOperator")
        
        // Apply cellular specific firewall rules
        applyCellularFirewallRules(networkOperator)
    }
    
    override fun onBind(intent: Intent?): IBinder? = null
}
```

### **App Monitoring**

```kotlin
// App Usage Monitoring
class AppMonitoringService : Service() {
    
    private val packageManager by lazy { packageManager }
    private val usageStatsManager by lazy {
        getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
    }
    
    fun getInstalledApps(): List<ApplicationInfo> {
        return packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
    }
    
    fun getAppNetworkUsage(packageName: String, timeRange: Long): NetworkUsageStats {
        val endTime = System.currentTimeMillis()
        val startTime = endTime - timeRange
        
        val networkStatsManager = getSystemService(Context.NETWORK_STATS_SERVICE) as NetworkStatsManager
        
        try {
            val uid = packageManager.getApplicationInfo(packageName, 0).uid
            
            // Get mobile data usage
            val mobileBucket = networkStatsManager.querySummaryForUser(
                ConnectivityManager.TYPE_MOBILE,
                "",
                startTime,
                endTime,
                uid
            )
            
            // Get Wi-Fi data usage
            val wifiBucket = networkStatsManager.querySummaryForUser(
                ConnectivityManager.TYPE_WIFI,
                "",
                startTime,
                endTime,
                uid
            )
            
            return NetworkUsageStats(
                packageName = packageName,
                mobileRxBytes = mobileBucket?.rxBytes ?: 0,
                mobileTxBytes = mobileBucket?.txBytes ?: 0,
                wifiRxBytes = wifiBucket?.rxBytes ?: 0,
                wifiTxBytes = wifiBucket?.txBytes ?: 0,
                timeRange = timeRange
            )
            
        } catch (e: Exception) {
            Log.e("ZehraSec", "Error getting network usage for $packageName: ${e.message}")
            return NetworkUsageStats(packageName, 0, 0, 0, 0, timeRange)
        }
    }
    
    fun getSuspiciousApps(): List<SuspiciousAppInfo> {
        val suspiciousApps = mutableListOf<SuspiciousAppInfo>()
        
        for (app in getInstalledApps()) {
            val suspicionScore = calculateSuspicionScore(app)
            if (suspicionScore > SUSPICION_THRESHOLD) {
                suspiciousApps.add(
                    SuspiciousAppInfo(
                        packageName = app.packageName,
                        appName = packageManager.getApplicationLabel(app).toString(),
                        suspicionScore = suspicionScore,
                        reasons = getSuspicionReasons(app)
                    )
                )
            }
        }
        
        return suspiciousApps
    }
    
    private fun calculateSuspicionScore(app: ApplicationInfo): Int {
        var score = 0
        
        // Check permissions
        try {
            val packageInfo = packageManager.getPackageInfo(app.packageName, PackageManager.GET_PERMISSIONS)
            val permissions = packageInfo.requestedPermissions
            
            if (permissions != null) {
                for (permission in permissions) {
                    when (permission) {
                        Manifest.permission.READ_SMS,
                        Manifest.permission.RECEIVE_SMS,
                        Manifest.permission.SEND_SMS -> score += 2
                        
                        Manifest.permission.RECORD_AUDIO,
                        Manifest.permission.CAMERA -> score += 2
                        
                        Manifest.permission.ACCESS_FINE_LOCATION,
                        Manifest.permission.ACCESS_COARSE_LOCATION -> score += 1
                        
                        Manifest.permission.READ_CONTACTS,
                        Manifest.permission.READ_CALL_LOG -> score += 2
                        
                        Manifest.permission.SYSTEM_ALERT_WINDOW -> score += 3
                        
                        Manifest.permission.DEVICE_ADMIN -> score += 3
                    }
                }
            }
        } catch (e: Exception) {
            Log.e("ZehraSec", "Error analyzing app permissions: ${e.message}")
        }
        
        // Check if app is from unknown source
        if ((app.flags and ApplicationInfo.FLAG_SYSTEM) == 0) {
            // Not a system app
            try {
                val installer = packageManager.getInstallerPackageName(app.packageName)
                if (installer != "com.android.vending" && installer != "com.google.android.packageinstaller") {
                    score += 2 // Sideloaded app
                }
            } catch (e: Exception) {
                score += 1
            }
        }
        
        // Check network usage patterns
        val networkUsage = getAppNetworkUsage(app.packageName, TimeUnit.DAYS.toMillis(7))
        val totalUsage = networkUsage.mobileRxBytes + networkUsage.mobileTxBytes + 
                        networkUsage.wifiRxBytes + networkUsage.wifiTxBytes
        
        if (totalUsage > 100 * 1024 * 1024) { // More than 100MB in a week
            score += 1
        }
        
        return score
    }
    
    override fun onBind(intent: Intent?): IBinder? = null
    
    companion object {
        private const val SUSPICION_THRESHOLD = 5
    }
}

data class NetworkUsageStats(
    val packageName: String,
    val mobileRxBytes: Long,
    val mobileTxBytes: Long,
    val wifiRxBytes: Long,
    val wifiTxBytes: Long,
    val timeRange: Long
)

data class SuspiciousAppInfo(
    val packageName: String,
    val appName: String,
    val suspicionScore: Int,
    val reasons: List<String>
)
```

### **Malware Detection**

```kotlin
// Malware Detection Engine
class MalwareDetectionEngine(private val context: Context) {
    
    private val virusTotalApi = VirusTotalApi()
    private val localSignatureDb = LocalSignatureDatabase(context)
    
    suspend fun scanApp(packageName: String): ScanResult {
        val scanResult = ScanResult(packageName)
        
        try {
            // Get app info
            val appInfo = context.packageManager.getApplicationInfo(packageName, 0)
            val apkPath = appInfo.sourceDir
            
            // Calculate file hash
            val fileHash = calculateSHA256(apkPath)
            scanResult.fileHash = fileHash
            
            // Check local signature database
            val localResult = localSignatureDb.checkSignature(fileHash)
            if (localResult.isMalicious) {
                scanResult.isMalicious = true
                scanResult.detectionReason = "Local signature match: ${localResult.signatureName}"
                return scanResult
            }
            
            // Check with VirusTotal API
            val vtResult = virusTotalApi.checkHash(fileHash)
            if (vtResult.positives > 0) {
                scanResult.isMalicious = true
                scanResult.detectionReason = "VirusTotal detection: ${vtResult.positives}/${vtResult.total}"
                scanResult.virusTotalResult = vtResult
            }
            
            // Behavioral analysis
            val behaviorResult = analyzeBehavior(packageName)
            if (behaviorResult.isSuspicious) {
                scanResult.isSuspicious = true
                scanResult.suspiciousActivities = behaviorResult.suspiciousActivities
            }
            
            // Static analysis
            val staticResult = performStaticAnalysis(apkPath)
            if (staticResult.hasRiskyCode) {
                scanResult.hasRiskyCode = true
                scanResult.riskyCodePatterns = staticResult.riskyPatterns
            }
            
        } catch (e: Exception) {
            scanResult.error = e.message
            Log.e("ZehraSec", "Error scanning app $packageName: ${e.message}")
        }
        
        return scanResult
    }
    
    private fun calculateSHA256(filePath: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val file = File(filePath)
        
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            
            while (input.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
    
    private suspend fun analyzeBehavior(packageName: String): BehaviorAnalysisResult {
        val result = BehaviorAnalysisResult()
        
        try {
            // Check network connections
            val networkConnections = getAppNetworkConnections(packageName)
            val suspiciousConnections = networkConnections.filter { connection ->
                isSuspiciousConnection(connection)
            }
            
            if (suspiciousConnections.isNotEmpty()) {
                result.isSuspicious = true
                result.suspiciousActivities.add("Suspicious network connections detected")
            }
            
            // Check file system access
            val fileAccess = getAppFileAccess(packageName)
            if (fileAccess.accessesSystemFiles) {
                result.isSuspicious = true
                result.suspiciousActivities.add("Accesses system files")
            }
            
            // Check for root access attempts
            if (checkRootAccessAttempts(packageName)) {
                result.isSuspicious = true
                result.suspiciousActivities.add("Attempts to gain root access")
            }
            
        } catch (e: Exception) {
            Log.e("ZehraSec", "Error in behavior analysis: ${e.message}")
        }
        
        return result
    }
    
    private fun performStaticAnalysis(apkPath: String): StaticAnalysisResult {
        val result = StaticAnalysisResult()
        
        try {
            // Extract and analyze APK
            val apkFile = File(apkPath)
            val zipFile = ZipFile(apkFile)
            
            // Analyze AndroidManifest.xml
            val manifestEntry = zipFile.getEntry("AndroidManifest.xml")
            if (manifestEntry != null) {
                val manifestData = zipFile.getInputStream(manifestEntry).readBytes()
                analyzeManifest(manifestData, result)
            }
            
            // Analyze DEX files
            val dexEntries = zipFile.entries().asSequence().filter { it.name.endsWith(".dex") }
            for (dexEntry in dexEntries) {
                val dexData = zipFile.getInputStream(dexEntry).readBytes()
                analyzeDex(dexData, result)
            }
            
            zipFile.close()
            
        } catch (e: Exception) {
            Log.e("ZehraSec", "Error in static analysis: ${e.message}")
        }
        
        return result
    }
    
    private fun analyzeManifest(manifestData: ByteArray, result: StaticAnalysisResult) {
        // Analyze AndroidManifest.xml for suspicious patterns
        val manifestString = String(manifestData)
        
        // Check for suspicious permissions
        val riskyPermissions = listOf(
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.DEVICE_ADMIN",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.WRITE_SECURE_SETTINGS"
        )
        
        for (permission in riskyPermissions) {
            if (manifestString.contains(permission)) {
                result.hasRiskyCode = true
                result.riskyPatterns.add("Risky permission: $permission")
            }
        }
    }
    
    private fun analyzeDex(dexData: ByteArray, result: StaticAnalysisResult) {
        // Analyze DEX bytecode for suspicious patterns
        val dexString = String(dexData)
        
        // Check for suspicious API calls
        val suspiciousApis = listOf(
            "Runtime.getRuntime().exec",
            "ProcessBuilder",
            "su",
            "Cipher",
            "DexClassLoader",
            "reflection"
        )
        
        for (api in suspiciousApis) {
            if (dexString.contains(api)) {
                result.hasRiskyCode = true
                result.riskyPatterns.add("Suspicious API call: $api")
            }
        }
    }
}

data class ScanResult(
    val packageName: String,
    var fileHash: String = "",
    var isMalicious: Boolean = false,
    var isSuspicious: Boolean = false,
    var hasRiskyCode: Boolean = false,
    var detectionReason: String = "",
    var suspiciousActivities: MutableList<String> = mutableListOf(),
    var riskyCodePatterns: MutableList<String> = mutableListOf(),
    var virusTotalResult: VirusTotalResult? = null,
    var error: String? = null
)

data class BehaviorAnalysisResult(
    var isSuspicious: Boolean = false,
    var suspiciousActivities: MutableList<String> = mutableListOf()
)

data class StaticAnalysisResult(
    var hasRiskyCode: Boolean = false,
    var riskyPatterns: MutableList<String> = mutableListOf()
)
```

---

## 🔐 **Security Features**

### **Device Encryption**

```kotlin
// Device Encryption Manager
class DeviceEncryptionManager(private val context: Context) {
    
    private val devicePolicyManager by lazy {
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    }
    
    fun isDeviceEncrypted(): Boolean {
        return devicePolicyManager.storageEncryptionStatus == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE
    }
    
    fun requireEncryption(): Boolean {
        return try {
            devicePolicyManager.setStorageEncryption(
                ComponentName(context, ZehraSecDeviceAdminReceiver::class.java),
                true
            )
            true
        } catch (e: SecurityException) {
            Log.e("ZehraSec", "Failed to require encryption: ${e.message}")
            false
        }
    }
    
    fun getEncryptionStatus(): EncryptionStatus {
        return when (devicePolicyManager.storageEncryptionStatus) {
            DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED -> EncryptionStatus.UNSUPPORTED
            DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> EncryptionStatus.INACTIVE
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVATING -> EncryptionStatus.ACTIVATING
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE -> EncryptionStatus.ACTIVE
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> EncryptionStatus.ACTIVE_DEFAULT_KEY
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER -> EncryptionStatus.ACTIVE_PER_USER
            else -> EncryptionStatus.UNKNOWN
        }
    }
}

enum class EncryptionStatus {
    UNSUPPORTED,
    INACTIVE,
    ACTIVATING,
    ACTIVE,
    ACTIVE_DEFAULT_KEY,
    ACTIVE_PER_USER,
    UNKNOWN
}
```

### **Biometric Authentication**

```kotlin
// Biometric Authentication
class BiometricAuthManager(private val context: Context) {
    
    fun isBiometricSupported(): Boolean {
        return BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) == BiometricManager.BIOMETRIC_SUCCESS
    }
    
    fun authenticateUser(
        activity: androidx.fragment.app.FragmentActivity,
        onSuccess: () -> Unit,
        onError: (String) -> Unit
    ) {
        val biometricPrompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(context),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    onSuccess()
                }
                
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    onError(errString.toString())
                }
                
                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    onError("Authentication failed")
                }
            }
        )
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("ZehraSec Authentication")
            .setSubtitle("Authenticate to access ZehraSec settings")
            .setNegativeButtonText("Cancel")
            .build()
        
        biometricPrompt.authenticate(promptInfo)
    }
}
```

---

## 📊 **Monitoring & Analytics**

### **Real-time Dashboard**

```kotlin
// Dashboard Activity
class DashboardActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityDashboardBinding
    private lateinit var networkMonitor: NetworkMonitor
    private lateinit var threatMonitor: ThreatMonitor
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDashboardBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupDashboard()
        startMonitoring()
    }
    
    private fun setupDashboard() {
        // Initialize dashboard components
        setupNetworkStatusCard()
        setupThreatDetectionCard()
        setupAppMonitoringCard()
        setupSystemHealthCard()
    }
    
    private fun setupNetworkStatusCard() {
        binding.networkStatusCard.apply {
            setOnClickListener {
                startActivity(Intent(this@DashboardActivity, NetworkDetailActivity::class.java))
            }
        }
        
        // Update network status
        updateNetworkStatus()
    }
    
    private fun updateNetworkStatus() {
        lifecycleScope.launch {
            val networkStats = networkMonitor.getCurrentStats()
            
            binding.apply {
                uploadSpeedText.text = formatDataRate(networkStats.uploadSpeed)
                downloadSpeedText.text = formatDataRate(networkStats.downloadSpeed)
                totalDataText.text = formatDataSize(networkStats.totalData)
                activeConnectionsText.text = networkStats.activeConnections.toString()
            }
        }
    }
    
    private fun setupThreatDetectionCard() {
        binding.threatDetectionCard.apply {
            setOnClickListener {
                startActivity(Intent(this@DashboardActivity, ThreatDetailActivity::class.java))
            }
        }
        
        // Update threat status
        updateThreatStatus()
    }
    
    private fun updateThreatStatus() {
        lifecycleScope.launch {
            val threatStats = threatMonitor.getCurrentStats()
            
            binding.apply {
                threatsBlockedText.text = threatStats.threatsBlocked.toString()
                lastThreatText.text = threatStats.lastThreat ?: "None"
                threatLevelText.text = threatStats.threatLevel.name
                
                // Update threat level color
                val color = when (threatStats.threatLevel) {
                    ThreatLevel.LOW -> ContextCompat.getColor(this@DashboardActivity, R.color.green)
                    ThreatLevel.MEDIUM -> ContextCompat.getColor(this@DashboardActivity, R.color.yellow)
                    ThreatLevel.HIGH -> ContextCompat.getColor(this@DashboardActivity, R.color.orange)
                    ThreatLevel.CRITICAL -> ContextCompat.getColor(this@DashboardActivity, R.color.red)
                }
                threatLevelIndicator.setColorFilter(color)
            }
        }
    }
    
    private fun formatDataRate(bytesPerSecond: Long): String {
        return when {
            bytesPerSecond < 1024 -> "$bytesPerSecond B/s"
            bytesPerSecond < 1024 * 1024 -> "${bytesPerSecond / 1024} KB/s"
            else -> "${bytesPerSecond / (1024 * 1024)} MB/s"
        }
    }
    
    private fun formatDataSize(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "${bytes / 1024} KB"
            bytes < 1024 * 1024 * 1024 -> "${bytes / (1024 * 1024)} MB"
            else -> "${bytes / (1024 * 1024 * 1024)} GB"
        }
    }
}
```

---

## 🛠️ **Troubleshooting**

### **Common Android Issues**

#### **VPN Connection Issues**
```kotlin
// VPN Troubleshooting
class VpnTroubleshooter {
    
    fun diagnoseVpnIssues(context: Context): List<VpnIssueInfo> {
        val issues = mutableListOf<VpnIssueInfo>()
        
        // Check VPN permission
        if (!hasVpnPermission(context)) {
            issues.add(VpnIssueInfo(
                "VPN Permission",
                "VPN permission not granted",
                "Request VPN permission in settings"
            ))
        }
        
        // Check battery optimization
        if (isBatteryOptimized(context)) {
            issues.add(VpnIssueInfo(
                "Battery Optimization",
                "App is battery optimized",
                "Disable battery optimization for ZehraSec"
            ))
        }
        
        // Check data saver mode
        if (isDataSaverEnabled(context)) {
            issues.add(VpnIssueInfo(
                "Data Saver",
                "Data saver is enabled",
                "Allow unrestricted data usage for ZehraSec"
            ))
        }
        
        return issues
    }
    
    private fun hasVpnPermission(context: Context): Boolean {
        return VpnService.prepare(context) == null
    }
    
    private fun isBatteryOptimized(context: Context): Boolean {
        val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            !powerManager.isIgnoringBatteryOptimizations(context.packageName)
        } else {
            false
        }
    }
    
    private fun isDataSaverEnabled(context: Context): Boolean {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            connectivityManager.restrictBackgroundStatus == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED
        } else {
            false
        }
    }
}

data class VpnIssueInfo(
    val title: String,
    val description: String,
    val solution: String
)
```

#### **Performance Issues**
```kotlin
// Performance Optimizer
class PerformanceOptimizer(private val context: Context) {
    
    fun optimizePerformance(): OptimizationResult {
        val result = OptimizationResult()
        
        // Clear cache
        clearCache()
        result.optimizations.add("Cache cleared")
        
        // Optimize database
        optimizeDatabase()
        result.optimizations.add("Database optimized")
        
        // Reduce memory usage
        reduceMemoryUsage()
        result.optimizations.add("Memory usage reduced")
        
        // Optimize network settings
        optimizeNetworkSettings()
        result.optimizations.add("Network settings optimized")
        
        return result
    }
    
    private fun clearCache() {
        try {
            val cacheDir = context.cacheDir
            deleteRecursively(cacheDir)
        } catch (e: Exception) {
            Log.e("ZehraSec", "Failed to clear cache: ${e.message}")
        }
    }
    
    private fun optimizeDatabase() {
        // Optimize SQLite database
        val dbHelper = DatabaseHelper(context)
        dbHelper.optimizeDatabase()
    }
    
    private fun reduceMemoryUsage() {
        // Force garbage collection
        System.gc()
        
        // Clear image cache
        Glide.get(context).clearMemory()
    }
    
    private fun deleteRecursively(file: File) {
        if (file.isDirectory) {
            file.listFiles()?.forEach { deleteRecursively(it) }
        }
        file.delete()
    }
}

data class OptimizationResult(
    val optimizations: MutableList<String> = mutableListOf(),
    val errors: MutableList<String> = mutableListOf()
)
```

---

## 📋 **Best Practices**

### **Android Security Best Practices**
1. **Keep OS Updated**: Install security patches promptly
2. **App Permissions**: Review and limit app permissions
3. **Unknown Sources**: Avoid installing apps from unknown sources
4. **Screen Lock**: Use strong screen lock with biometrics
5. **Device Encryption**: Enable full device encryption
6. **Network Security**: Use secure Wi-Fi networks
7. **Remote Wipe**: Enable remote device wipe capability

### **Performance Best Practices**
1. **Battery Optimization**: Exclude ZehraSec from battery optimization
2. **Background Apps**: Limit unnecessary background apps
3. **Storage Management**: Keep sufficient free storage space
4. **Network Monitoring**: Monitor data usage patterns
5. **Regular Maintenance**: Perform regular app maintenance

### **Enterprise Deployment Best Practices**
1. **MDM Integration**: Use mobile device management
2. **Policy Enforcement**: Implement security policies
3. **App Whitelisting**: Control allowed applications
4. **Network Isolation**: Segregate enterprise traffic
5. **Compliance Monitoring**: Monitor compliance status

---

## 📞 **Support**

### **Android-Specific Support**
- **Email**: android-support@zehrasec.com
- **Documentation**: https://docs.zehrasec.com/android
- **Community**: https://community.zehrasec.com/android
- **Google Play**: https://play.google.com/store/apps/details?id=com.zehrasec.firewall

### **Enterprise Support**
- **Enterprise Sales**: enterprise@zehrasec.com
- **MDM Integration**: mdm-support@zehrasec.com
- **Technical Support**: 24/7 enterprise support available

---

*ZehraSec Advanced Firewall - Android Platform Guide*
