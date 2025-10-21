<?php
/**
 * .htaccess Beheer Systeem
 * Beveiligd mappen met Apache Basic Authentication
 */

// ============================================
// CONFIGURATIE
// ============================================

define('PROTECTED_DIR', __DIR__);
define('HTACCESS_PATH', PROTECTED_DIR . '/.htaccess');
define('MIN_PASSWORD_LENGTH', 6);

// ============================================
// SESSIE & CSRF
// ============================================

session_start();

function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// ============================================
// HELPER FUNCTIES
// ============================================

function generateRandomFilename() {
    return '.htpasswd_' . bin2hex(random_bytes(6));
}

function safeEscape($string) {
    return str_replace(['"', '\\'], ['\"', '\\\\'], $string);
}

function redirectPage($title, $message, $url, $seconds = 2) {
    return '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta http-equiv="refresh" content="' . $seconds . ';url=' . htmlspecialchars($url) . '"></head><body>
    <div style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; max-width: 600px; margin: 100px auto; padding: 30px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; text-align: center;">
        <h2 style="color: #155724; margin-top: 0;">' . htmlspecialchars($title) . '</h2>
        <p style="color: #155724;">' . htmlspecialchars($message) . '</p>
    </div></body></html>';
}

function csrfField() {
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(generateCSRFToken()) . '">';
}

// ============================================
// HTACCESS FUNCTIES
// ============================================

class HtaccessManager {
    private $htaccessPath;
    private $cachedContent = null;
    
    public function __construct($path) {
        $this->htaccessPath = $path;
    }
    
    private function getContent() {
        if ($this->cachedContent === null && file_exists($this->htaccessPath)) {
            $this->cachedContent = file_get_contents($this->htaccessPath);
        }
        return $this->cachedContent;
    }
    
    private function saveContent($content) {
        $this->cachedContent = $content;
        return file_put_contents($this->htaccessPath, $content) !== false;
    }
    
    public function exists() {
        return file_exists($this->htaccessPath);
    }
    
    public function getHtpasswdPath() {
        $content = $this->getContent();
        if ($content && preg_match('/AuthUserFile\s+(.+)/', $content, $matches)) {
            return trim($matches[1]);
        }
        return null;
    }
    
    public function getAuthName() {
        $content = $this->getContent();
        if ($content && preg_match('/AuthName\s+"([^"]+)"/', $content, $matches)) {
            return $matches[1];
        }
        return 'Beveiligde Area';
    }
    
    public function isActive() {
        $content = $this->getContent();
        return $content && 
               strpos($content, 'Require valid-user') !== false && 
               strpos($content, '# Require valid-user') === false;
    }
    
    public function create($htpasswdPath, $authName, $activate = false) {
        $requireLine = $activate ? 'Require valid-user' : '# Require valid-user';
        $content = "AuthType Basic\nAuthName \"" . safeEscape($authName) . "\"\nAuthUserFile $htpasswdPath\n$requireLine";
        return $this->saveContent($content);
    }
    
    public function activate() {
        $content = $this->getContent();
        if (!$content) return false;
        
        $content = str_replace('# Require valid-user', 'Require valid-user', $content);
        return $this->saveContent($content);
    }
    
    public function deactivate() {
        $content = $this->getContent();
        if (!$content) return false;
        
        $content = preg_replace('/^Require valid-user$/m', '# Require valid-user', $content);
        return $this->saveContent($content);
    }
    
    public function updateAuthName($newAuthName) {
        $content = $this->getContent();
        if (!$content) return false;
        
        $content = preg_replace(
            '/AuthName\s+"[^"]+"/',
            'AuthName "' . safeEscape($newAuthName) . '"',
            $content
        );
        return $this->saveContent($content);
    }
    
    public function delete() {
        if ($this->exists()) {
            $this->cachedContent = null;
            return unlink($this->htaccessPath);
        }
        return true;
    }
}

// ============================================
// GEBRUIKERS FUNCTIES
// ============================================

class UserManager {
    private $htpasswdPath;
    
    public function __construct($htpasswdPath) {
        $this->htpasswdPath = $htpasswdPath;
    }
    
    public function exists() {
        return $this->htpasswdPath && file_exists($this->htpasswdPath);
    }
    
    public function create() {
        if (!$this->htpasswdPath) return false;
        
        if (touch($this->htpasswdPath)) {
            chmod($this->htpasswdPath, 0644);
            return true;
        }
        return false;
    }
    
    public function getAll() {
        if (!$this->exists()) return [];
        
        $users = [];
        $lines = file($this->htpasswdPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        
        foreach ($lines as $line) {
            if (strpos($line, ':') !== false) {
                list($username, $hash) = explode(':', $line, 2);
                $users[$username] = $hash;
            }
        }
        
        return $users;
    }
    
    private function save($users) {
        $content = '';
        foreach ($users as $username => $hash) {
            $content .= "$username:$hash\n";
        }
        return file_put_contents($this->htpasswdPath, $content) !== false;
    }
    
    public function add($username, $password) {
        $users = $this->getAll();
        
        $hash = password_hash($password, PASSWORD_BCRYPT);
        $hash = str_replace('$2y$', '$2b$', $hash);
        
        $users[$username] = $hash;
        return $this->save($users);
    }
    
    public function delete($username) {
        $users = $this->getAll();
        
        if (!isset($users[$username])) {
            return false;
        }
        
        unset($users[$username]);
        return $this->save($users);
    }
    
    public function changePassword($username, $newPassword) {
        $users = $this->getAll();
        
        if (!isset($users[$username])) {
            return false;
        }
        
        $hash = password_hash($newPassword, PASSWORD_BCRYPT);
        $hash = str_replace('$2y$', '$2b$', $hash);
        
        $users[$username] = $hash;
        return $this->save($users);
    }
}

// ============================================
// INITIALISATIE
// ============================================

$htaccess = new HtaccessManager(HTACCESS_PATH);
$htpasswdPath = $htaccess->getHtpasswdPath();
$users = new UserManager($htpasswdPath);

$message = '';
$error = '';

// ============================================
// ACTIES VERWERKEN
// ============================================

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $error = 'Ongeldige aanvraag. Probeer het opnieuw.';
    } else {
        $action = $_POST['action'] ?? '';
        
        switch ($action) {
            case 'setup':
                $authName = trim($_POST['auth_name'] ?? 'Beveiligde Area');
                
                if (empty($authName)) {
                    $error = 'AuthName mag niet leeg zijn';
                } else {
                    $randomFilename = generateRandomFilename();
                    $newHtpasswdPath = PROTECTED_DIR . '/' . $randomFilename;
                    
                    if (file_exists($newHtpasswdPath)) {
                        $error = 'Er ging iets mis. Probeer opnieuw.';
                        break;
                    }
                    
                    if ($htaccess->create($newHtpasswdPath, $authName, false)) {
                        $tempUsers = new UserManager($newHtpasswdPath);
                        if ($tempUsers->create()) {
                            $message = "Wachtwoordbestand aangemaakt: $randomFilename. Voeg nu gebruikers toe.";
                            $htpasswdPath = $newHtpasswdPath;
                            $users = new UserManager($htpasswdPath);
                        } else {
                            $htaccess->delete();
                            $error = 'Fout bij aanmaken wachtwoordbestand. Check schrijfrechten.';
                        }
                    } else {
                        $error = 'Fout bij aanmaken .htaccess. Check schrijfrechten.';
                    }
                }
                break;
                
            case 'add_user':
                $username = trim($_POST['username'] ?? '');
                $password = $_POST['password'] ?? '';
                
                if (empty($username) || empty($password)) {
                    $error = 'Gebruikersnaam en wachtwoord zijn verplicht';
                } elseif (!preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
                    $error = 'Gebruikersnaam mag alleen letters, cijfers, - en _ bevatten';
                } elseif (strlen($password) < MIN_PASSWORD_LENGTH) {
                    $error = 'Wachtwoord moet minimaal ' . MIN_PASSWORD_LENGTH . ' tekens lang zijn';
                } else {
                    $allUsers = $users->getAll();
                    if (isset($allUsers[$username])) {
                        $error = "Gebruiker '$username' bestaat al";
                    } elseif ($users->add($username, $password)) {
                        $message = "Gebruiker '$username' toegevoegd";
                    } else {
                        $error = 'Fout bij toevoegen gebruiker';
                    }
                }
                break;
                
            case 'delete_user':
                $username = $_POST['username'] ?? '';
                
                if ($users->delete($username)) {
                    $message = "Gebruiker '$username' verwijderd";
                } else {
                    $error = 'Fout bij verwijderen gebruiker';
                }
                break;
                
            case 'change_password':
                $username = $_POST['username'] ?? '';
                $newPassword = $_POST['new_password'] ?? '';
                
                if (empty($newPassword)) {
                    $error = 'Nieuw wachtwoord is verplicht';
                } elseif (strlen($newPassword) < MIN_PASSWORD_LENGTH) {
                    $error = 'Wachtwoord moet minimaal ' . MIN_PASSWORD_LENGTH . ' tekens lang zijn';
                } else {
                    if ($users->changePassword($username, $newPassword)) {
                        $message = "Wachtwoord van '$username' gewijzigd";
                    } else {
                        $error = 'Fout bij wijzigen wachtwoord';
                    }
                }
                break;
                
            case 'change_authname':
                $newAuthName = trim($_POST['new_authname'] ?? '');
                
                if (empty($newAuthName)) {
                    $error = 'AuthName mag niet leeg zijn';
                } else {
                    if ($htaccess->updateAuthName($newAuthName)) {
                        $message = "AuthName gewijzigd naar '$newAuthName'";
                    } else {
                        $error = 'Fout bij wijzigen AuthName';
                    }
                }
                break;
                
            case 'activate':
                $allUsers = $users->getAll();
                
                if (empty($allUsers)) {
                    $error = 'Voeg eerst minimaal één gebruiker toe voordat je de beveiliging activeert.';
                } else {
                    if ($htaccess->activate()) {
                        echo redirectPage('Beveiliging geactiveerd', 'Over 2 seconden word je doorgestuurd en moet je inloggen...', $_SERVER['PHP_SELF'], 2);
                        exit;
                    } else {
                        $error = 'Fout bij activeren beveiliging. Check schrijfrechten.';
                    }
                }
                break;
                
            case 'deactivate':
                if ($htaccess->deactivate()) {
                    $message = 'Beveiliging uitgeschakeld. Beveiliging kan later opnieuw geactiveerd worden.';
                } else {
                    $error = 'Fout bij uitschakelen beveiliging.';
                }
                break;
        }
    }
}

// ============================================
// STATUS BEPALEN
// ============================================

$allUsers = $users->getAll();
$setupNeeded = !$htaccess->exists() || !$users->exists();
$isActive = $htaccess->isActive();
$currentAuthName = $htaccess->getAuthName();

?>
<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>.htaccess Beheer</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; 
            margin: 0; 
            padding: 40px; 
            background-color: #f8f9fa; 
            color: #212529;
        }
        .container { 
            max-width: 900px; 
            margin: 0 auto; 
            background: white; 
            padding: 40px; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 { 
            color: #343a40; 
            margin-bottom: 30px; 
            font-size: 2.2em;
            font-weight: 600;
        }
        h2 { 
            color: #495057;
            margin-top: 30px;
            margin-bottom: 20px;
            font-size: 1.5em;
            font-weight: 500;
        }
        .section {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 20px;
            margin: 20px 0;
        }
        .form-group {
            margin: 20px 0;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #495057;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            max-width: 400px;
            padding: 12px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 0 0.2rem rgba(0,123,255,.25);
        }
        button {
            background-color: #007bff;
            color: white;
            border: none;
            padding: 12px 24px;
            font-size: 16px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 500;
            transition: background-color 0.2s;
        }
        button:hover {
            background-color: #0056b3;
        }
        button:disabled {
            background-color: #6c757d;
            cursor: not-allowed;
        }
        button.danger {
            background-color: #dc3545;
            padding: 6px 12px;
            font-size: 13px;
        }
        button.danger:hover {
            background-color: #c82333;
        }
        button.secondary {
            background-color: #6c757d;
            padding: 6px 12px;
            font-size: 13px;
            margin-left: 5px;
        }
        button.secondary:hover {
            background-color: #5a6268;
        }
        button.success {
            background-color: #28a745;
            padding: 12px 30px;
            font-size: 16px;
        }
        button.success:hover {
            background-color: #218838;
        }
        button.warning {
            background-color: #ffc107;
            color: #000;
        }
        button.warning:hover {
            background-color: #e0a800;
        }
        .success {
            background: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
            border: 1px solid #c3e6cb;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
            border: 1px solid #f5c6cb;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        th {
            background: #007bff;
            color: white;
            font-weight: 500;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .info {
            background: #d1ecf1;
            color: #0c5460;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
            border: 1px solid #bee5eb;
        }
        .warning {
            background: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
            border: 1px solid #ffeaa7;
        }
        .steps {
            background: #e7f3ff;
            padding: 20px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .step {
            display: flex;
            align-items: center;
            margin: 15px 0;
            padding: 10px;
            background: white;
            border-radius: 4px;
        }
        .step-number {
            background: #007bff;
            color: white;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 500;
            margin-right: 15px;
            flex-shrink: 0;
        }
        .step-number.done {
            background: #28a745;
        }
        .step-number.current {
            background: #ffc107;
            color: #000;
        }
        code {
            background: #f4f4f4;
            color: #e83e8c;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            font-size: 0.9em;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            background-color: #28a745;
            color: white;
            border-radius: 3px;
            font-size: 12px;
            font-weight: 500;
            margin-left: 10px;
        }
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #6c757d;
        }
        .config-section {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .config-header {
            background-color: #e9ecef;
            padding: 12px 16px;
            border-bottom: 1px solid #dee2e6;
            cursor: pointer;
            font-weight: 500;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .config-header:hover {
            background-color: #dee2e6;
        }
        .config-content {
            padding: 20px;
        }
        .toggle-btn {
            background-color: #6c757d;
            color: white;
            border: none;
            padding: 4px 8px;
            font-size: 12px;
            border-radius: 3px;
            cursor: pointer;
        }
        .toggle-btn:hover {
            background-color: #5a6268;
        }
        .hidden {
            display: none;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
        }
        .modal-content {
            background: white;
            max-width: 500px;
            margin: 100px auto;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }
        .modal-buttons {
            margin-top: 20px;
            text-align: right;
        }
        .activate-box {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 25px;
            border-radius: 4px;
            margin: 20px 0;
            text-align: center;
        }
        .activate-box h3 {
            margin-top: 0;
            color: #856404;
        }
        small {
            color: #6c757d;
            font-size: 0.875em;
        }
        @media (max-width: 768px) {
            body {
                padding: 20px;
            }
            .container {
                padding: 20px;
            }
            h1 {
                font-size: 1.8em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>.htaccess Beheer Systeem</h1>

        <?php if ($message): ?>
            <div class="success"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <?php if ($setupNeeded): ?>
            
            <div class="steps">
                <h2 style="margin-top: 0;">Setup proces</h2>
                <div class="step">
                    <div class="step-number current">1</div>
                    <div>Start setup (maak wachtwoordbestand aan)</div>
                </div>
                <div class="step">
                    <div class="step-number">2</div>
                    <div>Voeg gebruikers toe</div>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <div>Activeer beveiliging</div>
                </div>
            </div>

            <div class="section">
                <h2>Stap 1: Setup starten</h2>
                <p>Configureer de beveiliging. Het wachtwoordbestand krijgt automatisch een willekeurige naam.</p>
                <form method="POST">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="setup">
                    <div class="form-group">
                        <label>Login Prompt Tekst (AuthName)</label>
                        <input type="text" name="auth_name" value="Beveiligde Area" placeholder="bijv. Mijn Privé Bestanden" required>
                        <br><small>Deze tekst verschijnt in het login popup venster</small>
                    </div>
                    <button type="submit">Setup starten</button>
                </form>
            </div>

        <?php elseif (!$isActive): ?>
            
            <div class="steps">
                <h2 style="margin-top: 0;">Setup proces</h2>
                <div class="step">
                    <div class="step-number done">1</div>
                    <div>Start setup (maak wachtwoordbestand aan)</div>
                </div>
                <div class="step">
                    <div class="step-number current">2</div>
                    <div>Voeg gebruikers toe</div>
                </div>
                <div class="step">
                    <div class="step-number">3</div>
                    <div>Activeer beveiliging</div>
                </div>
            </div>

            <div class="warning">
                <strong>Let op:</strong> De map is nog NIET beveiligd. Voeg eerst minimaal één gebruiker toe voordat je de beveiliging activeert.
            </div>

            <div class="info">
                Wachtwoordbestand: <code><?= htmlspecialchars(basename($htpasswdPath)) ?></code><br>
                Login Prompt: <strong><?= htmlspecialchars($currentAuthName) ?></strong>
            </div>

            <div class="config-section">
                <div class="config-header" onclick="toggleConfig()">
                    <span>Configuratie</span>
                    <button type="button" class="toggle-btn" id="config-toggle">Toon</button>
                </div>
                <div class="config-content hidden" id="config-content">
                    <h2 style="margin-top: 0;">Login Prompt wijzigen</h2>
                    <form method="POST">
                        <?= csrfField() ?>
                        <input type="hidden" name="action" value="change_authname">
                        <div class="form-group">
                            <label>Nieuwe Login Prompt Tekst</label>
                            <input type="text" name="new_authname" value="<?= htmlspecialchars($currentAuthName) ?>" placeholder="bijv. Mijn Privé Bestanden" required>
                            <br><small>Deze tekst verschijnt in het login popup venster</small>
                        </div>
                        <button type="submit">Opslaan</button>
                    </form>
                </div>
            </div>

            <div class="section">
                <h2>Stap 2: Gebruikers toevoegen</h2>
                <form method="POST">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="add_user">
                    <div class="form-group">
                        <label>Gebruikersnaam</label>
                        <input type="text" name="username" placeholder="bijv. jan" required pattern="[a-zA-Z0-9_-]+">
                        <br><small>Alleen letters, cijfers, - en _</small>
                    </div>
                    <div class="form-group">
                        <label>Wachtwoord</label>
                        <input type="password" name="password" placeholder="Minimaal <?= MIN_PASSWORD_LENGTH ?> tekens" required minlength="<?= MIN_PASSWORD_LENGTH ?>">
                    </div>
                    <button type="submit">Gebruiker toevoegen</button>
                </form>
            </div>

            <?php if (!empty($allUsers)): ?>
                <div class="section">
                    <h2>Toegevoegde gebruikers (<?= count($allUsers) ?>)</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Gebruikersnaam</th>
                                <th style="width: 100px;">Acties</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($allUsers as $username => $hash): ?>
                                <tr>
                                    <td><strong><?= htmlspecialchars($username) ?></strong></td>
                                    <td>
                                        <form method="POST" style="display: inline;">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="action" value="delete_user">
                                            <input type="hidden" name="username" value="<?= htmlspecialchars($username) ?>">
                                            <button type="submit" class="danger" onclick="return confirm('Verwijderen?')">
                                                Verwijderen
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <div class="activate-box">
                    <h3>Stap 3: Klaar om te activeren</h3>
                    <p>Je hebt <strong><?= count($allUsers) ?></strong> gebruiker(s) aangemaakt.</p>
                    <p>Klik op de knop hieronder om de beveiliging te activeren.<br>
                    <strong>Let op:</strong> Na activatie moet je inloggen om deze pagina te zien.</p>
                    <form method="POST" style="margin-top: 15px;" onsubmit="return confirm('Weet je zeker dat je de beveiliging wilt activeren? Je moet daarna inloggen.');">
                        <?= csrfField() ?>
                        <input type="hidden" name="action" value="activate">
                        <button type="submit" class="success">Beveiliging activeren</button>
                    </form>
                </div>
            <?php endif; ?>

        <?php else: ?>
            
            <div class="info">
                <strong>Beveiliging actief</strong> <span class="badge">Actief</span><br>
                Beveiligde map: <?= htmlspecialchars(PROTECTED_DIR) ?><br>
                Wachtwoordbestand: <code><?= htmlspecialchars(basename($htpasswdPath)) ?></code><br>
                Login Prompt: <strong><?= htmlspecialchars($currentAuthName) ?></strong><br>
                Aantal gebruikers: <span class="badge"><?= count($allUsers) ?></span>
            </div>

            <div class="config-section">
                <div class="config-header" onclick="toggleConfig()">
                    <span>Configuratie</span>
                    <button type="button" class="toggle-btn" id="config-toggle">Toon</button>
                </div>
                <div class="config-content hidden" id="config-content">
                    <h2 style="margin-top: 0;">Login Prompt wijzigen</h2>
                    <form method="POST">
                        <?= csrfField() ?>
                        <input type="hidden" name="action" value="change_authname">
                        <div class="form-group">
                            <label>Nieuwe Login Prompt Tekst</label>
                            <input type="text" name="new_authname" value="<?= htmlspecialchars($currentAuthName) ?>" placeholder="bijv. Mijn Privé Bestanden" required>
                            <br><small>Deze tekst verschijnt in het login popup venster</small>
                        </div>
                        <button type="submit">Opslaan</button>
                    </form>
                </div>
            </div>

            <div class="config-section">
                <div class="config-header" onclick="toggleAdvanced()">
                    <span>Geavanceerde opties</span>
                    <button type="button" class="toggle-btn" id="advanced-toggle">Toon</button>
                </div>
                <div class="config-content hidden" id="advanced-content">
                    <h2 style="margin-top: 0;">Beveiliging uitschakelen</h2>
                    <p>Schakel de beveiliging tijdelijk uit. De map wordt publiek toegankelijk, maar gebruikers blijven bewaard.</p>
                    <form method="POST" onsubmit="return confirm('Weet je zeker dat je de beveiliging tijdelijk wilt uitschakelen?');">
                        <?= csrfField() ?>
                        <input type="hidden" name="action" value="deactivate">
                        <button type="submit" class="warning">Beveiliging uitschakelen</button>
                    </form>
                </div>
            </div>

            <div class="section">
                <h2>Nieuwe gebruiker toevoegen</h2>
                <form method="POST">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="add_user">
                    <div class="form-group">
                        <label>Gebruikersnaam</label>
                        <input type="text" name="username" placeholder="bijv. jan" required pattern="[a-zA-Z0-9_-]+">
                        <br><small>Alleen letters, cijfers, - en _</small>
                    </div>
                    <div class="form-group">
                        <label>Wachtwoord</label>
                        <input type="password" name="password" placeholder="Minimaal <?= MIN_PASSWORD_LENGTH ?> tekens" required minlength="<?= MIN_PASSWORD_LENGTH ?>">
                    </div>
                    <button type="submit">Gebruiker toevoegen</button>
                </form>
            </div>

            <div class="section">
                <h2>Gebruikers beheren</h2>
                <?php if (empty($allUsers)): ?>
                    <div class="empty-state">
                        <p>Nog geen gebruikers aangemaakt.</p>
                    </div>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>Gebruikersnaam</th>
                                <th style="width: 220px;">Acties</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($allUsers as $username => $hash): ?>
                                <tr>
                                    <td><strong><?= htmlspecialchars($username) ?></strong></td>
                                    <td>
                                        <button class="secondary" onclick="showChangePassword('<?= htmlspecialchars($username, ENT_QUOTES) ?>')">
                                            Wachtwoord
                                        </button>
                                        <form method="POST" style="display: inline;">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="action" value="delete_user">
                                            <input type="hidden" name="username" value="<?= htmlspecialchars($username) ?>">
                                            <button type="submit" class="danger" onclick="return confirm('Weet je zeker dat je <?= htmlspecialchars($username) ?> wil verwijderen?')">
                                                Verwijderen
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <div class="info">
                <strong>Tip:</strong> Alle bestanden in deze map zijn automatisch beveiligd door .htaccess.
            </div>

        <?php endif; ?>
    </div>

    <div id="passwordModal" class="modal">
        <div class="modal-content">
            <h2>Wachtwoord wijzigen</h2>
            <form method="POST">
                <?= csrfField() ?>
                <input type="hidden" name="action" value="change_password">
                <input type="hidden" name="username" id="modal_username">
                <div class="form-group">
                    <label>Nieuw wachtwoord voor <strong id="modal_username_display"></strong></label>
                    <input type="password" name="new_password" placeholder="Minimaal <?= MIN_PASSWORD_LENGTH ?> tekens" required minlength="<?= MIN_PASSWORD_LENGTH ?>">
                </div>
                <div class="modal-buttons">
                    <button type="button" onclick="hideModal('passwordModal')" style="background: #6c757d;">Annuleren</button>
                    <button type="submit">Opslaan</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function showModal(modalId) {
            document.getElementById(modalId).style.display = 'block';
        }

        function hideModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        function showChangePassword(username) {
            document.getElementById('modal_username').value = username;
            document.getElementById('modal_username_display').textContent = username;
            showModal('passwordModal');
        }

        function toggleConfig() {
            const content = document.getElementById('config-content');
            const button = document.getElementById('config-toggle');
            
            if (content.classList.contains('hidden')) {
                content.classList.remove('hidden');
                button.textContent = 'Verberg';
            } else {
                content.classList.add('hidden');
                button.textContent = 'Toon';
            }
        }

        function toggleAdvanced() {
            const content = document.getElementById('advanced-content');
            const button = document.getElementById('advanced-toggle');
            
            if (content.classList.contains('hidden')) {
                content.classList.remove('hidden');
                button.textContent = 'Verberg';
            } else {
                content.classList.add('hidden');
                button.textContent = 'Toon';
            }
        }

        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
            }
        }
    </script>
</body>
</html>