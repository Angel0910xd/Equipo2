<?php
session_start();
require_once 'config/global.php';


$email = $password = "";
$email_err = $password_err = $login_err = "";

// Procesar el formulario
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Conexión a la base de datos
    $mysqli = new mysqli(DB_HOST, DB_USERNAME, DB_PASSWORD, DB_NAME);

    if ($mysqli->connect_error) {
        die("ERROR: No se pudo conectar a la base de datos. " . $mysqli->connect_error);
    }

    // Validar email
    if (empty(trim($_POST["email"]))) {
        $email_err = "Por favor, ingresa tu email.";
    } else {
        $email = trim($_POST["email"]);
    }

    // Validar contraseña
    if (empty(trim($_POST["password"]))) {
        $password_err = "Por favor, ingresa tu contraseña.";
    } else {
        $password = trim($_POST["password"]);
    }

    // Validar credenciales
    if (empty($email_err) && empty($password_err)) {
        $sql = "SELECT id, email, password FROM usuarios WHERE email = ?";

        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("s", $param_email);
            $param_email = $email;

            if ($stmt->execute()) {
                $stmt->store_result();

                if ($stmt->num_rows == 1) {
                    $stmt->bind_result($id, $email_db, $hashed_password);
                    if ($stmt->fetch()) {
                        if (password_verify($password, $hashed_password)) {
                            // Inicio de sesión exitoso
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["email"] = $email_db;

                            header("location: bennett.html");
                            exit;
                        } else {
                            $login_err = "Email o contraseña incorrectos.";
                        }
                    }
                } else {
                    $login_err = "Email o contraseña incorrectos.";
                }
            } else {
                $login_err = "¡Ups! Algo salió mal. Intenta más tarde.";
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
    <title>Login</title>
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
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background-color: var(--clr-alpha);
            outline: 2px solid var(--bg-dark);
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
            color: var(--bg-dark);
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
    </style>
</head>
<body>
<form class="form" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
    <h2>Inicio de Sesión</h2>

    <?php 
    if (!empty($login_err)) {
        echo '<div class="error-message">' . $login_err . '</div>';
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

    <span class="span"><a href="contraseña.php">¿Olvidaste tu contraseña?</a></span>

    <input class="submit" type="submit" value="Iniciar sesión" />

    <span class="span">¿No tienes cuenta? <a href="registro.php">Regístrate</a></span>
</form>
</body>
</html>
