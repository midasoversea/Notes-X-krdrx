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
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.WbSunny
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.GridView
import androidx.compose.material.icons.filled.ViewAgenda
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.NoteAdd
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.BorderStroke
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

private data class NoteCard(
    val id: String,
    val title: String,
    val data: VaultData,
    val label: String = "",
    val color: Int = 0,
    val pinned: Boolean = false,
    val updated: Long = System.currentTimeMillis()
)

private data class VaultStore(
    val notes: MutableList<NoteCard>,
    val darkTheme: Boolean = false,
    val gridMode: Boolean = true
) {
    fun json(): String = JSONObject().put("version", 2).put("darkTheme", darkTheme)
        .put("gridMode", gridMode).put("notes", JSONArray().also { array ->
            notes.forEach { note ->
                array.put(JSONObject().put("id", note.id).put("title", note.title)
                    .put("data", JSONObject(note.data.json())).put("label", note.label)
                    .put("color", note.color).put("pinned", note.pinned).put("updated", note.updated))
            }
        }).toString()

    companion object {
        fun parse(raw: String): VaultStore {
            val root = JSONObject(raw)
            if (root.has("notes")) {
                val array = root.getJSONArray("notes")
                val notes = MutableList(array.length()) { i ->
                    val item = array.getJSONObject(i)
                    NoteCard(
                        item.optString("id", java.util.UUID.randomUUID().toString()),
                        item.optString("title", "Tanpa judul"),
                        VaultData.parse(item.getJSONObject("data").toString()),
                        item.optString("label", ""), item.optInt("color", 0),
                        item.optBoolean("pinned", false), item.optLong("updated", System.currentTimeMillis())
                    )
                }
                return VaultStore(notes, root.optBoolean("darkTheme", false), root.optBoolean("gridMode", true))
            }
            // Migrasi otomatis format lama: satu spreadsheet menjadi kartu pertama.
            val legacy = VaultData.parse(raw)
            return VaultStore(mutableListOf(NoteCard(
                java.util.UUID.randomUUID().toString(), "Catatan Utama", legacy
            )))
        }
        fun empty() = VaultStore(mutableListOf())
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

    fun save(pin: String, data: VaultStore) {
        val random = SecureRandom()
        val salt = ByteArray(16).also(random::nextBytes)
        val iv = ByteArray(12).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(pin, salt), GCMParameterSpec(128, iv))
        val encrypted = cipher.doFinal(data.json().toByteArray(Charsets.UTF_8))
        file.writeBytes(byteArrayOf(1) + salt + iv + encrypted)
    }

    fun load(pin: String): VaultStore {
        val bytes = file.readBytes()
        require(bytes.size > 29 && bytes[0].toInt() == 1) { "Format vault tidak valid." }
        val salt = bytes.copyOfRange(1, 17)
        val iv = bytes.copyOfRange(17, 29)
        val encrypted = bytes.copyOfRange(29, bytes.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(pin, salt), GCMParameterSpec(128, iv))
        return VaultStore.parse(String(cipher.doFinal(encrypted), Charsets.UTF_8))
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
    var data by remember { mutableStateOf(VaultStore.empty()) }
    var pin by remember { mutableStateOf("") }
    var pinConfirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    var isSetup by remember { mutableStateOf(!crypto.exists()) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val saveMutex = remember { Mutex() }

    val bg = if (dark) DarkBg else LightBg
    val surface = if (dark) Color(0xFF193B36) else Color.White
    val text = if (dark) Color(0xFFE7F4F1) else Color(0xFF173B35)
    val scheme = if (dark) darkColorScheme(
        primary = Color(0xFF54D6C5), background = bg, surface = surface,
        onSurface = text, onBackground = text,
        primaryContainer = Color(0xFF24534C), onPrimaryContainer = Color(0xFFE7F4F1),
        outlineVariant = Color(0xFF52716C)
    ) else lightColorScheme(
        primary = Tosca, background = bg, surface = surface,
        onSurface = text, onBackground = text,
        primaryContainer = Color(0xFFD7F0EB), onPrimaryContainer = Color(0xFF173B35),
        outlineVariant = Color(0xFFB7C9C4)
    )

    MaterialTheme(colorScheme = scheme) {
        if (!unlocked) {
            LockScreen(isSetup, pin, { pin = it }, pinConfirm, { pinConfirm = it }, error, dark, busy) {
                if (!busy) {
                    if (isSetup && (pin.length < 10 || pin != pinConfirm)) {
                        error = "Kata sandi minimal 10 karakter dan konfirmasi harus sama."
                    } else if (pin.isBlank()) {
                        error = "Masukkan kata sandi terlebih dahulu."
                    } else {
                        busy = true
                        error = ""
                        val password = pin
                        scope.launch {
                            try {
                                val loaded = withContext(Dispatchers.IO) {
                                    if (isSetup) {
                                        val fresh = VaultStore.empty()
                                        crypto.save(password, fresh)
                                        fresh
                                    } else {
                                        crypto.load(password)
                                    }
                                }
                                data = loaded
                                dark = loaded.darkTheme
                                unlocked = true
                            } catch (_: Exception) {
                                error = if (isSetup) "Gagal membuat vault. Coba lagi." else "Kata sandi salah atau data vault rusak."
                                if (!isSetup) pin = ""
                            } finally {
                                busy = false
                            }
                        }
                    }
                }
            }
        } else {
            DisposableEffect(Unit) {
                windowSecure(context, true)
                onDispose { windowSecure(context, false) }
            }
            VaultHomeScreen(
                store = data.copy(darkTheme = dark),
                onStoreChange = { updated ->
                    data = updated
                    dark = updated.darkTheme
                    val password = pin
                    val snapshot = updated.copy(notes = updated.notes.map { note ->
                        note.copy(data = VaultData(note.data.columns.toMutableList(), note.data.rows.map { it.toMutableList() }.toMutableList()))
                    }.toMutableList())
                    scope.launch {
                        saveMutex.withLock { withContext(Dispatchers.IO) { crypto.save(password, snapshot) } }
                    }
                },
                onLock = {
                unlocked = false
                pin = ""
            )
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
    confirm: String, onConfirm: (String) -> Unit, error: String, dark: Boolean,
    busy: Boolean, submit: () -> Unit
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
        if (busy) {
            Spacer(Modifier.height(12.dp))
            CircularProgressIndicator()
            Text("Memproses enkripsi, tunggu sebentar...")
        }
        Spacer(Modifier.height(18.dp))
        Button(onClick = submit, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text(if (busy) "Memproses..." else if (setup) "Buat Vault" else "Buka")
        }
    }
}

@Composable
private fun VaultHomeScreen(
    store: VaultStore,
    onStoreChange: (VaultStore) -> Unit,
    onLock: () -> Unit
) {
    var activeId by remember { mutableStateOf<String?>(null) }
    var creating by remember { mutableStateOf(false) }
    var grid by remember(store.gridMode) { mutableStateOf(store.gridMode) }
    var showMeta by remember { mutableStateOf<NoteCard?>(null) }
    var search by remember { mutableStateOf("") }

    val active = store.notes.firstOrNull { it.id == activeId }
    if (active != null) {
        SpreadsheetScreen(
            note = active,
            onBack = { activeId = null },
            onChange = { changed ->
                onStoreChange(store.copy(notes = store.notes.map { if (it.id == changed.id) changed else it }.toMutableList()))
            }
        )
        return
    }

    if (creating) {
        NewNoteScreen(
            onCancel = { creating = false },
            onCreate = { title, label, color ->
                val note = NoteCard(java.util.UUID.randomUUID().toString(), title, VaultData.empty(), label, color)
                onStoreChange(store.copy(notes = (store.notes + note).toMutableList()))
                creating = false
                activeId = note.id
            }
        )
        return
    }

    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).padding(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.weight(1f)) {
                Text("Notes-X-krdrx", style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onBackground)
                Text("${store.notes.size} catatan", style = MaterialTheme.typography.labelSmall)
            }
            IconButton(onClick = { onStoreChange(store.copy(darkTheme = !store.darkTheme)) }) {
                Icon(if (store.darkTheme) Icons.Default.WbSunny else Icons.Default.DarkMode,
                    contentDescription = "Ganti tema")
            }
            IconButton(onClick = { grid = !grid; onStoreChange(store.copy(gridMode = grid)) }) {
                Icon(if (grid) Icons.Default.ViewAgenda else Icons.Default.GridView,
                    contentDescription = "Ganti tampilan")
            }
            IconButton(onClick = onLock) { Icon(Icons.Default.Lock, "Kunci") }
        }
        OutlinedTextField(search, { search = it }, modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("Cari judul, label, atau isi...") }, singleLine = true)
        Spacer(Modifier.height(10.dp))
        val sorted = store.notes.sortedWith(compareByDescending<NoteCard> { it.pinned }.thenByDescending { it.updated })
            .filter { search.isBlank() || it.title.contains(search, true) || it.label.contains(search, true) ||
                it.data.rows.any { row -> row.any { cell -> cell.contains(search, true) } } }
        if (grid) {
            androidx.compose.foundation.lazy.grid.LazyVerticalGrid(
                columns = androidx.compose.foundation.lazy.grid.GridCells.Fixed(2),
                modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(9.dp),
                horizontalArrangement = Arrangement.spacedBy(9.dp)
            ) {
                items(sorted.size) { index ->
                    NoteCardView(sorted[index], onOpen = { activeId = sorted[index].id },
                        onPin = { note -> onStoreChange(store.copy(notes = store.notes.map { if (it.id == note.id) it.copy(pinned = !it.pinned) else it }.toMutableList())) },
                        onMore = { showMeta = sorted[index] })
                }
            }
        } else {
            LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                itemsIndexed(sorted) { _, note ->
                    NoteCardView(note, onOpen = { activeId = note.id },
                        onPin = { item -> onStoreChange(store.copy(notes = store.notes.map { if (it.id == item.id) it.copy(pinned = !it.pinned) else it }.toMutableList())) },
                        onMore = { showMeta = note }, fullWidth = true)
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        ExtendedFloatingActionButton(
            onClick = { creating = true },
            modifier = Modifier.align(Alignment.End),
            icon = { Icon(Icons.Default.NoteAdd, null) },
            text = { Text("Buat Catatan") }
        )
    }

    if (showMeta != null) {
        val note = showMeta!!
        var title by remember(note.id) { mutableStateOf(note.title) }
        var label by remember(note.id) { mutableStateOf(note.label) }
        var color by remember(note.id) { mutableIntStateOf(note.color) }
        AlertDialog(
            onDismissRequest = { showMeta = null },
            title = { Text("Detail catatan") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(title, { title = it }, label = { Text("Judul") }, singleLine = true)
                    OutlinedTextField(label, { label = it }, label = { Text("Label") }, singleLine = true)
                    Text("Warna kartu")
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf(0, 1, 2, 3, 4).forEach { value ->
                            val colors = listOf(Color(0xFF80CBC4), Color(0xFF90CAF9), Color(0xFFA5D6A7), Color(0xFFFFCC80), Color(0xFFCE93D8))
                            Surface(
                                modifier = Modifier.size(30.dp).clickable { color = value },
                                color = colors[value], shape = RoundedCornerShape(50),
                                border = if (color == value) BorderStroke(3.dp, MaterialTheme.colorScheme.primary) else null
                            ) {}
                        }
                    }
                    TextButton(onClick = {
                        onStoreChange(store.copy(notes = store.notes.filterNot { it.id == note.id }.toMutableList()))
                        showMeta = null
                    }) { Text("Hapus catatan", color = MaterialTheme.colorScheme.error) }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    onStoreChange(store.copy(notes = store.notes.map {
                        if (it.id == note.id) it.copy(title = title.ifBlank { "Tanpa judul" }, label = label, color = color, updated = System.currentTimeMillis()) else it
                    }.toMutableList()))
                    showMeta = null
                }) { Text("Simpan") }
            },
            dismissButton = { TextButton(onClick = { showMeta = null }) { Text("Batal") } }
        )
    }
}

@Composable
private fun NoteCardView(
    note: NoteCard,
    onOpen: () -> Unit,
    onPin: (NoteCard) -> Unit,
    onMore: () -> Unit,
    fullWidth: Boolean = false
) {
    val palette = listOf(Color(0xFFE0F2F1), Color(0xFFE3F2FD), Color(0xFFE8F5E9), Color(0xFFFFF3E0), Color(0xFFF3E5F5))
    val darkPalette = listOf(Color(0xFF214A45), Color(0xFF243F59), Color(0xFF294A35), Color(0xFF55412A), Color(0xFF4A3454))
    val background = if (MaterialTheme.colorScheme.background == DarkBg) darkPalette[note.color.coerceIn(0,4)] else palette[note.color.coerceIn(0,4)]
    Surface(
        color = background, shape = RoundedCornerShape(12.dp),
        border = BorderStroke(0.8.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth().clickable { onOpen() }
    ) {
        Column(Modifier.padding(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(note.title, Modifier.weight(1f), fontWeight = FontWeight.Bold,
                    maxLines = 2, color = MaterialTheme.colorScheme.onBackground)
                IconButton(onClick = { onPin(note) }, modifier = Modifier.size(30.dp)) {
                    Icon(Icons.Default.PushPin, "Sematkan",
                        tint = if (note.pinned) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface)
                }
                IconButton(onClick = onMore, modifier = Modifier.size(30.dp)) {
                    Icon(Icons.Default.Settings, "Detail")
                }
            }
            if (note.label.isNotBlank()) Text(note.label, style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary)
            Text("${note.data.columns.size} kolom • ${note.data.rows.size} baris",
                style = MaterialTheme.typography.labelSmall)
            note.data.rows.take(3).forEach { row ->
                Text(row.filter { it.isNotBlank() }.joinToString("  •  ").take(90),
                    style = MaterialTheme.typography.bodySmall, maxLines = 1)
            }
        }
    }
}

@Composable
private fun NewNoteScreen(
    onCancel: () -> Unit,
    onCreate: (String, String, Int) -> Unit
) {
    var title by remember { mutableStateOf("") }
    var label by remember { mutableStateOf("") }
    var color by remember { mutableIntStateOf(0) }
    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onCancel) { Icon(Icons.Default.ArrowBack, "Kembali") }
            Text("Catatan baru", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        }
        OutlinedTextField(title, { title = it }, modifier = Modifier.fillMaxWidth(),
            label = { Text("Judul catatan") }, singleLine = true)
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(label, { label = it }, modifier = Modifier.fillMaxWidth(),
            label = { Text("Label (opsional)") }, singleLine = true)
        Spacer(Modifier.height(12.dp))
        Text("Warna kartu")
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            listOf(Color(0xFF80CBC4), Color(0xFF90CAF9), Color(0xFFA5D6A7), Color(0xFFFFCC80), Color(0xFFCE93D8)).forEachIndexed { index, shade ->
                Surface(modifier = Modifier.size(34.dp).clickable { color = index },
                    color = shade, shape = RoundedCornerShape(50),
                    border = if (color == index) BorderStroke(3.dp, MaterialTheme.colorScheme.primary) else null) {}
            }
        }
        Spacer(Modifier.height(20.dp))
        Button(onClick = { onCreate(title.trim().ifBlank { "Tanpa judul" }, label.trim(), color) },
            modifier = Modifier.fillMaxWidth()) { Text("Buat dan buka spreadsheet") }
    }
}

@Composable
private fun SpreadsheetScreen(
    note: NoteCard,
    onBack: () -> Unit,
    onChange: (NoteCard) -> Unit
) {
    var query by remember { mutableStateOf("") }
    var edit by remember { mutableStateOf<Triple<Int, Int, String>?>(null) }
    var columnDialog by remember { mutableStateOf(false) }
    var newColumn by remember { mutableStateOf("") }
    var renameColumn by remember { mutableStateOf<Int?>(null) }
    var renamedTitle by remember { mutableStateOf("") }
    val data = note.data
    val context = LocalContext.current
    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).padding(10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) { Icon(Icons.Default.ArrowBack, "Kembali") }
            Column(Modifier.weight(1f)) {
                Text(note.title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                if (note.label.isNotBlank()) Text(note.label, style = MaterialTheme.typography.labelSmall)
            }
            IconButton(onClick = { columnDialog = true }) { Icon(Icons.Default.Add, "Tambah kolom") }
        }
        OutlinedTextField(query, { query = it }, modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("Cari data...") }, singleLine = true)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { columnDialog = true }) { Text("+ Kolom") }
            OutlinedButton(onClick = {
                val rows = data.rows.map { it.toMutableList() }.toMutableList()
                rows.add(MutableList(data.columns.size) { "" })
                onChange(note.copy(data = data.copy(rows = rows), updated = System.currentTimeMillis()))
            }) { Text("+ Baris") }
        }
        val width = 132.dp
        val line = MaterialTheme.colorScheme.outlineVariant
        Row(Modifier.horizontalScroll(rememberScrollState())) {
            data.columns.forEachIndexed { col, title ->
                Surface(color = MaterialTheme.colorScheme.primaryContainer, border = BorderStroke(0.7.dp, line),
                    modifier = Modifier.width(width).height(40.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        TextButton(onClick = { renameColumn = col; renamedTitle = title }, modifier = Modifier.weight(1f)) {
                            Text(title, maxLines = 1, fontWeight = FontWeight.Bold)
                        }
                        IconButton(onClick = {
                            onChange(note.copy(data = data.copy(
                                columns = data.columns.toMutableList().also { it.removeAt(col) },
                                rows = data.rows.map { it.toMutableList().also { r -> if (col < r.size) r.removeAt(col) } }.toMutableList()
                            ), updated = System.currentTimeMillis()))
                        }, modifier = Modifier.size(26.dp)) { Icon(Icons.Default.Delete, null, modifier = Modifier.size(14.dp)) }
                    }
                }
            }
        }
        LazyColumn(Modifier.weight(1f)) {
            itemsIndexed(data.rows.mapIndexed { i, row -> i to row }.filter { (_, row) ->
                query.isBlank() || row.any { it.contains(query, true) }
            }) { _, pair ->
                val ri = pair.first
                Row(Modifier.horizontalScroll(rememberScrollState())) {
                    pair.second.forEachIndexed { ci, value ->
                        val password = data.columns.getOrNull(ci)?.let { it.contains("password", true) || it.contains("sandi", true) } == true
                        var reveal by remember(value, ri, ci) { mutableStateOf(false) }
                        Surface(color = MaterialTheme.colorScheme.surface, border = BorderStroke(0.7.dp, line),
                            modifier = Modifier.width(width).height(42.dp).clickable { edit = Triple(ri, ci, value) }) {
                            Row(Modifier.fillMaxSize().padding(horizontal = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                                Text(if (password && !reveal && value.isNotEmpty()) "••••••••" else value,
                                    Modifier.weight(1f), maxLines = 1, style = MaterialTheme.typography.bodySmall)
                                if (password && value.isNotEmpty()) IconButton(onClick = { reveal = !reveal }, modifier = Modifier.size(25.dp)) {
                                    Icon(if (reveal) Icons.Default.VisibilityOff else Icons.Default.Visibility, null, modifier = Modifier.size(14.dp))
                                }
                            }
                        }
                    }
                    Surface(color = MaterialTheme.colorScheme.surface, border = BorderStroke(0.7.dp, line),
                        modifier = Modifier.width(36.dp).height(42.dp)) {
                        IconButton(onClick = {
                            onChange(note.copy(data = data.copy(rows = data.rows.toMutableList().also { it.removeAt(ri) }),
                                updated = System.currentTimeMillis()))
                        }) { Icon(Icons.Default.Delete, "Hapus baris", modifier = Modifier.size(15.dp)) }
                    }
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
                onChange(note.copy(data = data.copy(rows = rows), updated = System.currentTimeMillis()))
                edit = null
            }) { Text("Simpan") } },
            dismissButton = { TextButton(onClick = { edit = null }) { Text("Batal") } })
    }
    if (renameColumn != null) {
        val index = renameColumn!!
        AlertDialog(onDismissRequest = { renameColumn = null }, title = { Text("Ubah nama kolom") },
            text = { OutlinedTextField(renamedTitle, { renamedTitle = it }, label = { Text("Nama kolom") }) },
            confirmButton = { TextButton(onClick = {
                if (renamedTitle.isNotBlank() && index in data.columns.indices) {
                    val columns = data.columns.toMutableList(); columns[index] = renamedTitle.trim()
                    onChange(note.copy(data = data.copy(columns = columns), updated = System.currentTimeMillis()))
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
                    onChange(note.copy(data = data.copy(
                        columns = (data.columns + newColumn.trim()).toMutableList(),
                        rows = data.rows.map { (it + "").toMutableList() }.toMutableList()
                    ), updated = System.currentTimeMillis()))
                    newColumn = ""
                }
                columnDialog = false
            }) { Text("Tambah") } },
            dismissButton = { TextButton(onClick = { columnDialog = false }) { Text("Batal") } })
    }
}
