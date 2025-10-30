<?php

require_once 'config/global.php';
$email = $new_password = $confirm_password = "";
$email_err = $new_password_err = $confirm_password_err = $general_err = $success_msg = "";

// Procesar formulario
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $mysqli = new mysqli(DB_HOST, DB_USERNAME, DB_PASSWORD, DB_NAME);

    if ($mysqli->connect_errno) {
        die("ERROR: No se pudo conectar a la base de datos. " . $mysqli->connect_error);
    }

    // Validar email
    if (empty(trim($_POST["email"]))) {
        $email_err = "Por favor, ingresa tu email.";
    } elseif (!filter_var(trim($_POST["email"]), FILTER_VALIDATE_EMAIL)) {
        $email_err = "El formato del email es inválido.";
    } else {
        $email = trim($_POST["email"]);
    }

    // Validar nueva contraseña solo si email es válido y existe en DB
    if (empty($email_err)) {
        // Verificar que el email existe
        $sql_check = "SELECT id FROM usuarios WHERE email = ?";
        if ($stmt_check = $mysqli->prepare($sql_check)) {
            $stmt_check->bind_param("s", $email);
            if ($stmt_check->execute()) {
                $stmt_check->store_result();
                if ($stmt_check->num_rows == 0) {
                    $email_err = "No existe una cuenta con ese email.";
                }
            } else {
                $general_err = "Error al verificar el email. Intenta más tarde.";
            }
            $stmt_check->close();
        }
    }

    // Si el email es válido y existe, validar nueva contraseña
    if (empty($email_err)) {
        if (empty(trim($_POST["new_password"]))) {
            $new_password_err = "Por favor, ingresa la nueva contraseña.";
        } elseif (strlen(trim($_POST["new_password"])) < 6) {
            $new_password_err = "La contraseña debe tener al menos 6 caracteres.";
        } else {
            $new_password = trim($_POST["new_password"]);
        }

        // Confirmar nueva contraseña
        if (empty(trim($_POST["confirm_password"]))) {
            $confirm_password_err = "Por favor, confirma la contraseña.";
        } else {
            $confirm_password = trim($_POST["confirm_password"]);
            if (empty($new_password_err) && ($new_password != $confirm_password)) {
                $confirm_password_err = "Las contraseñas no coinciden.";
            }
        }
    }

    // Si no hay errores, actualizar contraseña
    if (empty($email_err) && empty($new_password_err) && empty($confirm_password_err) && empty($general_err)) {
        $sql_update = "UPDATE usuarios SET password = ? WHERE email = ?";
        if ($stmt_update = $mysqli->prepare($sql_update)) {
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            $stmt_update->bind_param("ss", $hashed_password, $email);
            if ($stmt_update->execute()) {
                $success_msg = "Contraseña actualizada correctamente. Ya puedes iniciar sesión.";
                // Limpiar variables para que el formulario quede vacío
                $email = $new_password = $confirm_password = "";
            } else {
                $general_err = "Error al actualizar la contraseña. Intenta más tarde.";
            }
            $stmt_update->close();
        }
    }

    $mysqli->close();
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8" />
    <title>Cambiar Contraseña</title>
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
            max-width: 350px;
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
        .form input[type="email"],
        .form input[type="password"] {
            border-radius: 0.5rem;
            padding: 1rem 0.75rem;
            width: 100%;
            border: none;
            background-color: var(--clr-alpha);
            outline: 2px solid var(--bg-dark);
            color: var(--bg-light);
        }
        .form input[type="email"]:focus,
        .form input[type="password"]:focus {
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
<form class="form" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" novalidate>
    <h2>Cambiar Contraseña</h2>

    <?php 
    if (!empty($success_msg)) {
        echo '<div class="success-message">' . $success_msg . '</div>';
    }
    if (!empty($general_err)) {
        echo '<div class="error-message">' . $general_err . '</div>';
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
    <?php if (!empty($email_err)) echo '<span class="help-block">' . $email_err . '</span>'; ?>

    <span class="input-span">
        <label for="new_password" class="label">Nueva Contraseña</label>
        <input 
            type="password" 
            name="new_password" 
            id="new_password" 
            required
        />
    </span>
    <?php if (!empty($new_password_err)) echo '<span class="help-block">' . $new_password_err . '</span>'; ?>

    <span class="input-span">
        <label for="confirm_password" class="label">Confirmar Contraseña</label>
        <input 
            type="password" 
            name="confirm_password" 
            id="confirm_password" 
            required
        />
    </span>
    <?php if (!empty($confirm_password_err)) echo '<span class="help-block">' . $confirm_password_err . '</span>'; ?>

    <input class="submit" type="submit" value="Actualizar Contraseña" />
    <span class="input-span">
        <a href="login.php" style="color: var(--clr); text-decoration:none;">Volver a iniciar sesión</a>
    </span>
</form>
</body>
</html>

