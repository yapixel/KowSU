package me.weishu.kernelsu.ui.webui

import android.annotation.SuppressLint
import android.app.Activity
import android.app.ActivityManager
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.webkit.WebViewAssetLoader
import me.weishu.kernelsu.ui.util.createRootShell
import java.io.File
import androidx.core.net.toUri

@SuppressLint("SetJavaScriptEnabled")
class WebUIActivity : ComponentActivity() {
    private val rootShell by lazy { createRootShell(true) }
    private var webView: WebView? = null
    private lateinit var insets: Insets
    private lateinit var fileChooserLauncher: ActivityResultLauncher<Intent>
    private var filePathCallback: ValueCallback<Array<Uri>>? = null

    override fun onCreate(savedInstanceState: Bundle?) {

        // Enable edge to edge
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.isNavigationBarContrastEnforced = false
        }

        super.onCreate(savedInstanceState)

        fileChooserLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                val data = result.data
                var uris: Array<Uri>? = null
                data?.dataString?.let {
                    uris = arrayOf(it.toUri())
                }
                data?.clipData?.let { clipData ->
                    uris = Array(clipData.itemCount) { i -> clipData.getItemAt(i).uri }
                }
                filePathCallback?.onReceiveValue(uris)
                filePathCallback = null
            } else {
                filePathCallback?.onReceiveValue(null)
                filePathCallback = null
            }
        }

        val moduleId = intent.getStringExtra("id") ?: finishAndRemoveTask().let { return }
        val name = intent.getStringExtra("name") ?: finishAndRemoveTask().let { return }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            @Suppress("DEPRECATION")
            setTaskDescription(ActivityManager.TaskDescription("KernelSU - $name"))
        } else {
            val taskDescription = ActivityManager.TaskDescription.Builder().setLabel("KernelSU - $name").build()
            setTaskDescription(taskDescription)
        }

        val prefs = getSharedPreferences("settings", MODE_PRIVATE)
        WebView.setWebContentsDebuggingEnabled(prefs.getBoolean("enable_web_debugging", false))

        val moduleDir = "/data/adb/modules/${moduleId}"
        val webRoot = File("${moduleDir}/webroot")
        insets = Insets(0, 0, 0, 0)

        val webViewAssetLoader = WebViewAssetLoader.Builder()
            .setDomain("mui.kernelsu.org")
            .addPathHandler(
                "/",
                SuFilePathHandler(this, webRoot, rootShell) { insets }
            )
            .build()

        val webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(
                view: WebView,
                request: WebResourceRequest
            ): WebResourceResponse? {
                val url = request.url

                //POC: Handle ksu://icon/[packageName] to serve app icon via WebView
                if (url.scheme.equals("ksu", ignoreCase = true) && url.host.equals("icon", ignoreCase = true)) {
                    val packageName = url.path?.substring(1)
                    if (!packageName.isNullOrEmpty()) {
                        val icon = AppIconUtil.loadAppIconSync(this@WebUIActivity, packageName, 512)
                        if (icon != null) {
                            val stream = java.io.ByteArrayOutputStream()
                            icon.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, stream)
                            val inputStream = java.io.ByteArrayInputStream(stream.toByteArray())
                            return WebResourceResponse("image/png", null, inputStream)
                        }
                    }
                }

                return webViewAssetLoader.shouldInterceptRequest(url)
            }
        }

        val webView = WebView(this).apply {
            webView = this
            setBackgroundColor(Color.TRANSPARENT)
            val density = resources.displayMetrics.density

            ViewCompat.setOnApplyWindowInsetsListener(this) { _, windowInsets ->
                val inset = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
                insets = Insets(
                    top = (inset.top / density).toInt(),
                    bottom = (inset.bottom / density).toInt(),
                    left = (inset.left / density).toInt(),
                    right = (inset.right / density).toInt()
                )
                WindowInsetsCompat.CONSUMED
            }
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = false
            addJavascriptInterface(WebViewInterface(this@WebUIActivity, this, moduleDir), "ksu")
            setWebViewClient(webViewClient)
            webChromeClient = object : WebChromeClient() {
                override fun onShowFileChooser(
                    webView: WebView?,
                    filePathCallback: ValueCallback<Array<Uri>>?,
                    fileChooserParams: FileChooserParams?
                ): Boolean {
                    this@WebUIActivity.filePathCallback = filePathCallback
                    val intent = fileChooserParams?.createIntent() ?: Intent(Intent.ACTION_GET_CONTENT).apply { type = "*/*" }
                    if (fileChooserParams?.mode == FileChooserParams.MODE_OPEN_MULTIPLE) {
                        intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
                    }
                    try {
                        fileChooserLauncher.launch(intent)
                    } catch (_: Exception) {
                        this@WebUIActivity.filePathCallback?.onReceiveValue(null)
                        this@WebUIActivity.filePathCallback = null
                        return false
                    }
                    return true
                }
            }
            loadUrl("https://mui.kernelsu.org/index.html")
        }

        setContentView(webView)
    }

    override fun onDestroy() {
        rootShell.runCatching { close() }
        webView?.apply {
            stopLoading()
            removeAllViews()
            destroy()
            webView = null
        }
        super.onDestroy()
    }
}
