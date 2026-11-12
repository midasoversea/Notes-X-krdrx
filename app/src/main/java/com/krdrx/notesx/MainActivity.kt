package com.krdrx.notesx

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

private data class VaultData(val columns: MutableList<String>, val rows: MutableList<MutableList<String>>) {
    fun json(): String = JSONObject().put("columns", JSONArray(columns)).put("rows", JSONArray().also { a ->
        rows.forEach { row -> a.put(JSONArray(row)) }
    }).toString()

    companion object {
        fun parse(raw: String): VaultData {
            val o = JSONObject(raw)
            val cols = o.getJSONArray("columns")
            val rowsJson = o.getJSONArray("rows")
            val columns = MutableList(cols.length()) { i -> cols.getString(i) }
            val rows = MutableList(rowsJson.length()) { r ->
                val arr = rowsJson.getJSONArray(r)
                MutableList(columns.size) { c -> if (c < arr.length()) arr.optString(c, "") else "" }
            }
            return VaultData(columns, rows)
        }
        fun empty() = VaultData(mutableListOf("Nama", "Username", "Password", "URL", "Catatan"), mutableListOf())
    }
}

private class VaultCrypto(private val context: Context) {
    private val file = File(context.filesDir, "vault.enc")
    fun exists() = file.exists()

    private fun key(pin: String, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(pin.toCharArray(), salt, 600_000, 256)
        val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        spec.clearPassword()
        return SecretKeySpec(bytes, "AES")
    }

    fun save(pin: String, data: VaultData) {
        val random = SecureRandom()
        val salt = ByteArray(16).also(random::nextBytes)
        val iv = ByteArray(12).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(pin, salt), GCMParameterSpec(128, iv))
        val encrypted = cipher.doFinal(data.json().toByteArray(Charsets.UTF_8))
        file.writeBytes(byteArrayOf(1) + salt + iv + encrypted)
    }

    fun load(pin: String): VaultData {
        val bytes = file.readBytes()
        require(bytes.size > 29 && bytes[0].toInt() == 1) { "Format vault tidak valid." }
        val salt = bytes.copyOfRange(1, 17)
        val iv = bytes.copyOfRange(17, 29)
        val encrypted = bytes.copyOfRange(29, bytes.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(pin, salt), GCMParameterSpec(128, iv))
        return VaultData.parse(String(cipher.doFinal(encrypted), Charsets.UTF_8))
    }
}

private val Tosca = Color(0xFF009688)
private val LightBg = Color(0xFFF4FAF8)
private val DarkBg = Color(0xFF102A27)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        setContent { NotesXApp() }
    }
}

@Composable
private fun NotesXApp() {
    val context = LocalContext.current
    val crypto = remember { VaultCrypto(context) }
    var dark by remember { mutableStateOf(false) }
    var unlocked by remember { mutableStateOf(false) }
    var data by remember { mutableStateOf(VaultData.empty()) }
    var pin by remember { mutableStateOf("") }
    var pinConfirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    var isSetup by remember { mutableStateOf(!crypto.exists()) }

    val bg = if (dark) DarkBg else LightBg
    val surface = if (dark) Color(0xFF193B36) else Color.White
    val text = if (dark) Color(0xFFE7F4F1) else Color(0xFF173B35)
    val scheme = if (dark) darkColorScheme(primary = Color(0xFF54D6C5), background = bg, surface = surface, onSurface = text)
                 else lightColorScheme(primary = Tosca, background = bg, surface = surface, onSurface = text)

    MaterialTheme(colorScheme = scheme) {
        if (!unlocked) {
            LockScreen(isSetup, pin, { pin = it }, pinConfirm, { pinConfirm = it }, error, dark) {
                if (isSetup) {
                    if (pin.length < 10 || pin != pinConfirm) {
                        error = "Kata sandi minimal 10 karakter dan konfirmasi harus sama."
                    } else {
                        data = VaultData.empty()
                        crypto.save(pin, data)
                        unlocked = true
                        error = ""
                    }
                } else {
                    try {
                        data = crypto.load(pin)
                        unlocked = true
                        error = ""
                    } catch (_: Exception) {
                        error = "PIN salah atau data vault rusak."
                        pin = ""
                    }
                }
            }
        } else {
            DisposableEffect(Unit) {
                windowSecure(context, true)
                onDispose { windowSecure(context, false) }
            }
            VaultScreen(data, dark, { dark = it }, { updated ->
                data = updated
                crypto.save(pin, data)
            }, {
                unlocked = false
                pin = ""
            })
            BackHandler { unlocked = false; pin = "" }
        }
    }
}

private fun windowSecure(context: Context, enabled: Boolean) {
    val activity = context as? ComponentActivity ?: return
    if (enabled) activity.window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    else activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
}

@Composable
private fun LockScreen(
    setup: Boolean, pin: String, onPin: (String) -> Unit,
    confirm: String, onConfirm: (String) -> Unit, error: String, dark: Boolean, submit: () -> Unit
) {
    Column(Modifier.fillMaxSize().background(if (dark) DarkBg else LightBg).padding(28.dp),
        verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(Icons.Default.Lock, null, tint = Tosca, modifier = Modifier.size(54.dp))
        Spacer(Modifier.height(16.dp))
        Text("Notes-X-krdrx", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text(if (setup) "Buat kata sandi utama (minimal 10 karakter)" else "Masukkan kata sandi untuk membuka vault")
        Spacer(Modifier.height(24.dp))
        OutlinedTextField(pin, onPin, label = { Text("Kata sandi utama") }, singleLine = true,
            visualTransformation = PasswordVisualTransformation())
        if (setup) {
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(confirm, onConfirm, label = { Text("Ulangi kata sandi") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), )
        }
        if (error.isNotBlank()) Text(error, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(8.dp))
        Spacer(Modifier.height(18.dp))
        Button(onClick = submit, modifier = Modifier.fillMaxWidth()) { Text(if (setup) "Buat Vault" else "Buka") }
    }
}

@Composable
private fun VaultScreen(data: VaultData, dark: Boolean, onTheme: (Boolean) -> Unit,
                        onSave: (VaultData) -> Unit, onLock: () -> Unit) {
    var query by remember { mutableStateOf("") }
    var showSettings by remember { mutableStateOf(false) }
    var edit by remember { mutableStateOf<Triple<Int, Int, String>?>(null) }
    var columnDialog by remember { mutableStateOf(false) }
    var newColumn by remember { mutableStateOf("") }\n    var renameColumn by remember { mutableStateOf<Int?>(null) }\n    var renamedTitle by remember { mutableStateOf("") }
    val context = LocalContext.current

    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).padding(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.weight(1f)) {
                Text("Notes-X-krdrx", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Text("Vault lokal terenkripsi", style = MaterialTheme.typography.labelSmall)
            }
            IconButton(onClick = { showSettings = true }) { Icon(Icons.Default.Settings, "Pengaturan") }
            IconButton(onClick = onLock) { Icon(Icons.Default.Lock, "Kunci") }
        }
        OutlinedTextField(query, { query = it }, modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("Cari data...") }, leadingIcon = { Icon(Icons.Default.Search, null) }, singleLine = true)
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { columnDialog = true }) { Icon(Icons.Default.Add, null); Text("Kolom") }
            OutlinedButton(onClick = { onSave(data.copy(rows = (data.rows + mutableListOf<String>().apply { repeat(data.columns.size) { add("") } }).toMutableList())) }) {
                Icon(Icons.Default.Add, null); Text("Baris")
            }
        }
        Spacer(Modifier.height(8.dp))
        Row(Modifier.horizontalScroll(rememberScrollState()).fillMaxWidth()) {
            data.columns.forEachIndexed { col, title ->
                Surface(color = MaterialTheme.colorScheme.primaryContainer, modifier = Modifier.width(150.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(6.dp)) {
                        TextButton(onClick = { renameColumn = col; renamedTitle = title }, modifier = Modifier.weight(1f)) { Text(title, fontWeight = FontWeight.Bold, maxLines = 1) }
                        IconButton(onClick = { onSave(data.copy(columns = data.columns.toMutableList().also { it.removeAt(col) },
                            rows = data.rows.map { it.toMutableList().also { row -> if (col < row.size) row.removeAt(col) } }.toMutableList())) },
                            modifier = Modifier.size(28.dp)) { Icon(Icons.Default.Delete, null, modifier = Modifier.size(16.dp)) }
                    }
                }
            }
        }
        HorizontalDivider()
        LazyColumn(Modifier.weight(1f)) {
            itemsIndexed(data.rows.mapIndexed { index, row -> index to row }.filter { (_, row) -> query.isBlank() || row.any { it.contains(query, true) } }) { _, indexedRow ->\n                val rowIndex = indexedRow.first\n                val row = indexedRow.second
                Row(Modifier.horizontalScroll(rememberScrollState())) {
                    row.forEachIndexed { colIndex, value ->
                        val isPassword = data.columns.getOrNull(colIndex)?.contains("password", true) == true ||
                            data.columns.getOrNull(colIndex)?.contains("sandi", true) == true
                        var reveal by remember(value, rowIndex, colIndex) { mutableStateOf(false) }
                        Surface(color = MaterialTheme.colorScheme.surface, modifier = Modifier.width(150.dp).padding(1.dp),
                            shape = RoundedCornerShape(4.dp)) {
                            Column(Modifier.padding(8.dp)) {
                                Text(data.columns.getOrNull(colIndex) ?: "", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                                Text(if (isPassword && !reveal && value.isNotEmpty()) "••••••••" else value,
                                    maxLines = 2, style = MaterialTheme.typography.bodyMedium)
                                Row {
                                    TextButton(onClick = { edit = Triple(rowIndex, colIndex, value) }) { Text("Edit") }
                                    if (isPassword) TextButton(onClick = { reveal = !reveal }) { Text(if (reveal) "Sembunyi" else "Lihat") }
                                    TextButton(onClick = {
                                        val clip = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                        clip.setPrimaryClip(ClipData.newPlainText("vault", value))
                                        android.os.Handler(context.mainLooper).postDelayed({
                                            if (clip.hasPrimaryClip()) clip.setPrimaryClip(ClipData.newPlainText("", ""))
                                        }, 30_000)
                                    }) { Text("Salin") }
                                }
                            }
                        }
                    }
                    IconButton(onClick = {
                        onSave(data.copy(rows = data.rows.toMutableList().also { it.removeAt(rowIndex) }))
                    }) { Icon(Icons.Default.Delete, "Hapus baris") }
                }
            }
        }
    }

    if (edit != null) {
        val e = edit!!
        var value by remember(e) { mutableStateOf(e.third) }
        AlertDialog(onDismissRequest = { edit = null }, title = { Text("Edit sel") },
            text = { OutlinedTextField(value, { value = it }, modifier = Modifier.fillMaxWidth()) },
            confirmButton = { TextButton(onClick = {
                val rows = data.rows.map { it.toMutableList() }.toMutableList()
                if (e.first in rows.indices && e.second in rows[e.first].indices) rows[e.first][e.second] = value
                onSave(data.copy(rows = rows)); edit = null
            }) { Text("Simpan") } },
            dismissButton = { TextButton(onClick = { edit = null }) { Text("Batal") } })
    }
    if (renameColumn != null) {
        val index = renameColumn!!
        AlertDialog(onDismissRequest = { renameColumn = null }, title = { Text("Ubah nama kolom") },
            text = { OutlinedTextField(renamedTitle, { renamedTitle = it }, label = { Text("Nama kolom") }) },
            confirmButton = { TextButton(onClick = {
                if (renamedTitle.isNotBlank() && index in data.columns.indices) {
                    val cols = data.columns.toMutableList()
                    cols[index] = renamedTitle.trim()
                    onSave(data.copy(columns = cols))
                }
                renameColumn = null
            }) { Text("Simpan") } },
            dismissButton = { TextButton(onClick = { renameColumn = null }) { Text("Batal") } })
    }
    if (columnDialog) {
        AlertDialog(onDismissRequest = { columnDialog = false }, title = { Text("Tambah kolom") },
            text = { OutlinedTextField(newColumn, { newColumn = it }, label = { Text("Nama kolom") }) },
            confirmButton = { TextButton(onClick = {
                if (newColumn.isNotBlank()) {
                    onSave(data.copy(columns = (data.columns + newColumn.trim()).toMutableList(),
                        rows = data.rows.map { (it + "").toMutableList() }.toMutableList()))
                    newColumn = ""
                }
                columnDialog = false
            }) { Text("Tambah") } },
            dismissButton = { TextButton(onClick = { columnDialog = false }) { Text("Batal") } })
    }
    if (showSettings) {
        AlertDialog(onDismissRequest = { showSettings = false }, title = { Text("Pengaturan") },
            text = { Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Tema gelap", Modifier.weight(1f)); Switch(dark, onTheme)
            } },
            confirmButton = { TextButton(onClick = { showSettings = false }) { Text("Tutup") } })
    }
}
