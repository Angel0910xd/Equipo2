<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
require_once 'config/global.php';


// Inicializar variables
$nombre = $email = $password = $confirm_password = "";
$nombre_err = $email_err = $password_err = $confirm_password_err = $register_err = $success_msg = "";

// Procesar formulario
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $mysqli = new mysqli(DB_HOST, DB_USERNAME, DB_PASSWORD, DB_NAME);

    if ($mysqli->connect_errno) {
        die("ERROR: No se pudo conectar a la base de datos. " . $mysqli->connect_error);
    }

    // Validar nombre
    if (empty(trim($_POST["nombre"]))) {
        $nombre_err = "Por favor, ingresa tu nombre.";
    } else {
        $nombre = trim($_POST["nombre"]);
    }

    // Validar email
    if (empty(trim($_POST["email"]))) {
        $email_err = "Por favor, ingresa un email.";
    } elseif (!filter_var(trim($_POST["email"]), FILTER_VALIDATE_EMAIL)) {
        $email_err = "El formato del email es inválido.";
    } else {
        $sql = "SELECT id FROM usuarios WHERE email = ?";
        if ($stmt = $mysqli->prepare($sql)) {
            $param_email = trim($_POST["email"]);
            $stmt->bind_param("s", $param_email);
            if ($stmt->execute()) {
                $stmt->store_result();
                if ($stmt->num_rows == 1) {
                    $email_err = "Este email ya está registrado.";
                } else {
                    $email = $param_email;
                }
            } else {
                $register_err = "Error al verificar email.";
            }
            $stmt->close();
        }
    }

    // Validar contraseña
    if (empty(trim($_POST["password"]))) {
        $password_err = "Por favor, ingresa una contraseña.";
    } elseif (strlen(trim($_POST["password"])) < 6) {
        $password_err = "La contraseña debe tener al menos 6 caracteres.";
    } else {
        $password = trim($_POST["password"]);
    }

    // Confirmar contraseña
    if (empty(trim($_POST["confirm_password"]))) {
        $confirm_password_err = "Por favor, confirma la contraseña.";
    } else {
        $confirm_password = trim($_POST["confirm_password"]);
        if (empty($password_err) && ($password != $confirm_password)) {
            $confirm_password_err = "Las contraseñas no coinciden.";
        }
    }

    // Insertar en base de datos
    if (empty($nombre_err) && empty($email_err) && empty($password_err) && empty($confirm_password_err)) {
        $sql = "INSERT INTO usuarios (email, password, nombre) VALUES (?, ?, ?)";
        if ($stmt = $mysqli->prepare($sql)) {
            $param_email = $email;
            $param_password = password_hash($password, PASSWORD_DEFAULT);
            $param_nombre = $nombre;

            $stmt->bind_param("sss", $param_email, $param_password, $param_nombre);
            if ($stmt->execute()) {
                $success_msg = "¡Registro exitoso! Ya puedes iniciar sesión.";
                $nombre = $email = "";
            } else {
                $register_err = "Error al intentar registrar el usuario.";
            }
            $stmt->close();
        }
    }

    $mysqli->close();
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Registro</title>
    <style>
        body {
            background-color: darkgray;
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }

        .form {
            --bg-light: #efefef;
            --bg-dark: #707070;
            --clr: #58bc82;
            --clr-alpha: #9c9c9c60;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1rem;
            width: 100%;
            max-width: 300px;
            padding: 2rem;
            background: #202020ff;
            border-radius: 1rem;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
            color: var(--bg-light);
        }

        .form h2 {
            color: var(--clr);
        }

        .form .input-span {
            width: 80%;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .form input[type="text"],
        .form input[type="email"],
        .form input[type="password"] {
            border-radius: 0.5rem;
            padding: 1rem 0.75rem;
            width: 100%;
            border: none;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background-color: var(--clr-alpha);
            outline: 2px solid var(--bg-dark);
            color: var(--bg-light);
        }

        .form input[type="email"]:focus,
        .form input[type="password"]:focus,
        .form input[type="text"]:focus {
            outline: 2px solid var(--clr);
        }

        .label {
            align-self: flex-start;
            color: var(--clr);
            font-weight: 600;
        }

        .form .submit {
            padding: 1rem 0.75rem;
            width: 100%;
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 0.5rem;
            border-radius: 3rem;
            background-color: var(--bg-dark);
            color: var(--bg-light);
            border: none;
            cursor: pointer;
            transition: all 300ms;
            font-weight: 600;
            font-size: 0.9rem;
        }

        .form .submit:hover {
            background-color: var(--clr);
            color: var(--bg-dark);
        }

        .span {
            text-decoration: none;
            color: var(--bg-light);
            font-size: 0.9rem;
        }

        .span a {
            color: var(--clr);
            text-decoration: none;
        }

        .help-block {
            color: red;
            font-size: 0.8rem;
            margin-top: -0.4rem;
            margin-bottom: 0.4rem;
            align-self: flex-start;
        }

        .error-message {
            background-color: #ffdddd;
            color: #d8000c;
            padding: 0.75rem;
            border-radius: 0.5rem;
            width: 100%;
            text-align: center;
            font-weight: 600;
            border: 1px solid #d8000c;
        }

        .success-message {
            background-color: #ddffdd;
            color: #155724;
            padding: 0.75rem;
            border-radius: 0.5rem;
            width: 100%;
            text-align: center;
            font-weight: 600;
            border: 1px solid #155724;
        }
    </style>
</head>
<body>
<form class="form" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
    <h2>Crear Cuenta</h2>

    <?php 
    if (!empty($success_msg)) {
        echo '<div class="success-message">' . $success_msg . '</div>';
    }
    if (!empty($register_err)) {
        echo '<div class="error-message">' . $register_err . '</div>';
    }
    ?>

    <span class="input-span">
        <label for="nombre" class="label">Nombre</label>
        <input 
            type="text" 
            name="nombre" 
            id="nombre"
            value="<?php echo htmlspecialchars($nombre); ?>" 
            required
        />
    </span>
    <?php 
    if (!empty($nombre_err)) {
        echo '<span class="help-block">' . $nombre_err . '</span>';
    }
    ?>

    <span class="input-span">
        <label for="email" class="label">Email</label>
        <input 
            type="email" 
            name="email" 
            id="email"
            value="<?php echo htmlspecialchars($email); ?>" 
            required
        />
    </span>
    <?php 
    if (!empty($email_err)) {
        echo '<span class="help-block">' . $email_err . '</span>';
    }
    ?>

    <span class="input-span">
        <label for="password" class="label">Contraseña</label>
        <input 
            type="password" 
            name="password" 
            id="password"
            required
        />
    </span>
    <?php 
    if (!empty($password_err)) {
        echo '<span class="help-block">' . $password_err . '</span>';
    }
    ?>

    <span class="input-span">
        <label for="confirm_password" class="label">Confirmar Contraseña</label>
        <input 
            type="password" 
            name="confirm_password" 
            id="confirm_password"
            required
        />
    </span>
    <?php 
    if (!empty($confirm_password_err)) {
        echo '<span class="help-block">' . $confirm_password_err . '</span>';
    }
    ?>

    <input class="submit" type="submit" value="Registrarse" />

    <span class="span">¿Ya tienes cuenta? <a href="login.php">Inicia Sesión</a></span>
</form>
</body>
</html>
