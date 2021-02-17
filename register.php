<?php
// Include config file
require_once "config.php";

//Prueba de funcion para encrypt password
function l2j_encrypt($password){
    return base64_encode(pack("H*", sha1(utf8_encode($password))));
}
 
// Define variables and initialize with empty values
$login = $password = $confirm_password = $email = "";
$login_err = $password_err = $confirm_password_err = $email_err = "";
 
// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){
 
    // Validate login
    if(empty(trim($_POST["login"]))){
        $login_err = "Por favor ingrese un usuario.";
    } else{
        // Prepare a select statement
        $sql = "SELECT id FROM accounts WHERE login = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_login);
            
            // Set parameters
            $param_login = trim($_POST["login"]);
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                /* store result */
                mysqli_stmt_store_result($stmt);
                
                if(mysqli_stmt_num_rows($stmt) == 1){
                    $login_err = "Este usuario ya fue tomado.";
                } else{
                    $login = trim($_POST["login"]);
                }
            } else{
                echo "Al parecer algo salió mal con el LOGIN.";
            }
        }
         
        // Close statement
        mysqli_stmt_close($stmt);
    }
    
    // Validate password
    if(empty(trim($_POST["password"]))){
        $password_err = "Por favor ingresa una contraseña.";     
    } elseif(strlen(trim($_POST["password"])) < 6){
        $password_err = "La contraseña al menos debe tener 6 caracteres.";
    } else{
        $password = trim($_POST["password"]);
    }
    
    // Validate confirm password
    if(empty(trim($_POST["confirm_password"]))){
        $confirm_password_err = "Confirma tu contraseña.";     
    } else{
        $confirm_password = trim($_POST["confirm_password"]);
        if(empty($password_err) && ($password != $confirm_password)){
            $confirm_password_err = "No coincide la contraseña.";
        }
    }
	
	// Validando el email
    if(empty(trim($_POST["email"]))){
        $email_err = "Por favor ingrese un correo.";
    } else{
        // Prepare a select statement
        $sql = "SELECT id FROM accounts WHERE email = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_email);
            
            // Set parameters
            $param_email = trim($_POST["email"]);
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                /* store result */
                mysqli_stmt_store_result($stmt);
                
                if(mysqli_stmt_num_rows($stmt) == 1){
                    $email_err = "Este correo ya fue tomado.";
                } else{
                    $email = trim($_POST["email"]);
                }
            } else{
                echo "Al parecer algo salió mal con el CORREO.";
            }
        }
         
        // Close statement
        mysqli_stmt_close($stmt);
    }
    
    // Check input errors before inserting in database
    if(empty($login_err) && empty($password_err) && empty($confirm_password_err)&& empty($email_err)){
        
        // Prepare an insert statement
        $sql = "INSERT INTO accounts (login, password, email) VALUES (?, ?, ?)";
         
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "ss", $param_login, $param_password, $param_email);
            
            // Set parameters
            $param_login = $login;
            $param_password = l2j_encrypt($password); // Creates a password hash --> password_hash($password, PASSWORD_DEFAULT);
            $param_email = $email;
			
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Redirect to email page
                header("location: cuentacreada.php");
            } else{
                echo "Algo salió mal AL ENVIAR LOS DATOS, por favor inténtalo de nuevo.";
            }
        }
         
        // Close statement
        mysqli_stmt_close($stmt);
    }
    
    // Close connection
    mysqli_close($link);
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Registro</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; }
        .wrapper{ width: 350px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Registro</h2>
        <p>Por favor complete este formulario para crear una cuenta.</p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group <?php echo (!empty($login_err)) ? 'has-error' : ''; ?>">
                <label>Usuario</label>
                <input type="text" name="login" class="form-control" value="<?php echo $login; ?>">
                <span class="help-block"><?php echo $login_err; ?></span>
            </div>   
            <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <label>Contraseña</label>
                <input type="password" name="password" class="form-control" value="<?php echo $password; ?>">
                <span class="help-block"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">
                <label>Confirmar Contraseña</label>
                <input type="password" name="confirm_password" class="form-control" value="<?php echo $confirm_password; ?>">
                <span class="help-block"><?php echo $confirm_password_err; ?></span>
            </div>
			<div class="form-group <?php echo (!empty($email_err)) ? 'has-error' : ''; ?>">
                <label>Correo</label>
                <input type="email" name="email" class="form-control" value="<?php echo $email; ?>">
                <span class="help-block"><?php echo $email_err; ?></span>
            </div>    
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Ingresar">
                <input type="reset" class="btn btn-default" value="Borrar">
            </div>
            <p>¿Ya tienes una cuenta? <a href="login.php">Ingresa aquí</a>.</p>
        </form>
    </div>    
</body>
</html>
