<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>MicroServizio1 ProgettoSaos</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.12.0/styles/monokai-sublime.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.12.0/highlight.min.js"></script>
    <script>
        hljs.configure({
            tabReplace: '    ',
        });
        hljs.initHighlightingOnLoad();
    </script>
    <style>body {
    position: relative;
}

h1 {
    margin-top: 5px;
}

h1, h2, h3, h4 {
    color: #2b2b2b;
}

h2:after {
    content: ' ';
}

h5 {
    font-weight: bold;
}

h1 a, h2 a, h3 a, h4 a, h5 a, h6 a {
    display: none;
    position: absolute;
    margin-left: 8px;
}

h1:hover a, h2:hover a, h3:hover a, h4:hover a, h5:hover a, h6:hover a {
    color: #a5a5a5;
    display: initial;
}

.nav.nav-tabs > li > a {
    padding-top: 4px;
    padding-bottom: 4px;
}

.tab-content {
    padding-top: 8px;
}

.table {
    margin-bottom: 8px;
}

pre {
    border-radius: 0px;
    border: none;
}

pre code {
    margin: -9.5px;
}

.request {
    margin-top: 12px;
    margin-bottom: 24px;
}

.response-text-sample {
    padding: 0px !important;
}

.response-text-sample pre {
    margin-bottom: 0px;
}


#sidebar-wrapper {
    z-index: 1000;
    position: fixed;
    left: 250px;
    width: 250px;
    height: 100%;
    margin-left: -250px;
    overflow-y: auto;
    overflow-x: hidden;
    background: #2b2b2b;
    padding-top: 20px;
}

#sidebar-wrapper ul {
    width: 250px;
}

#sidebar-wrapper ul li {
    margin-right: 10px;
}

#sidebar-wrapper ul li a:hover {
    background: inherit;
    text-decoration: none;
}

#sidebar-wrapper ul li a {
    display: block;
    color: #ECF0F1;
    padding: 6px 15px;
}

#sidebar-wrapper ul li ul {
    padding-left: 25px;
}

#sidebar-wrapper ul li ul li a {
    padding: 1px 0px;
}

#sidebar-wrapper ul li a:hover,
#sidebar-wrapper ul li a:focus {
    color: #e0c46c;
    border-right: solid 1px #e0c46c;
}

#sidebar-wrapper ul li.active > a {
    color: #e0c46c;
    border-right: solid 3px #e0c46c;
}

#sidebar-wrapper ul li:not(.active) ul {
    display: none;
}

#page-content-wrapper {
    width: 100%;
    position: absolute;
    padding: 15px 15px 15px 250px;
}
</style>
</head>
<body data-spy="scroll" data-target=".scrollspy">
<div id="sidebar-wrapper">
    <div class="scrollspy">
    <ul id="main-menu" data-spy="affix" class="nav">
        <li>
            <a href="#doc-general-notes">General notes</a>
        </li>
        
        <li>
            <a href="#doc-api-detail">API detail</a>
        </li>
        
        <li>
            <a href="#request-login-uente-e-admin">Login uente e admin</a>
        </li>
        
        <li>
            <a href="#request-nuovo-admin">Nuovo Admin</a>
        </li>
        
        <li>
            <a href="#request-registrazione-user">Registrazione User</a>
        </li>
        
        
    </ul>
</div>

</div>
<div id="page-content-wrapper">
    <div class="container-fluid">
        <div class="row">
            <div class="col-lg-12">
                <h1>MicroServizio1 ProgettoSaos</h1>

                <h2 id="doc-general-notes">
                    General notes
                    <a href="#doc-general-notes"><i class="glyphicon glyphicon-link"></i></a>
                </h2>

                <p>Il microservizio &ldquo;Microservizio1&rdquo; è progettato per gestire l&rsquo;autenticazione e la registrazione degli utenti in un&rsquo;applicazione. Utilizza <strong>JWT</strong> (JSON Web Token) per l&rsquo;autenticazione stateless e differenzia gli accessi in base ai ruoli degli utenti, come &ldquo;USER&rdquo; e &ldquo;ADMIN&rdquo;. Fornisce endpoint per la registrazione, il login, e specifiche azioni riservate agli amministratori, garantendo la sicurezza attraverso Spring Security e la configurazione di filtri per l&rsquo;accesso basato sui token.EndFragment</p>


                

                <h2 id="doc-api-detail">
                    API detail
                    <a href="#doc-api-detail"><i class="glyphicon glyphicon-link"></i></a>
                </h2>

                
                
                <div class="request">

                    <h3 id="request-login-uente-e-admin">
                        Login uente e admin
                        <a href="#request-login-uente-e-admin"><i class="glyphicon glyphicon-link"></i></a>
                    </h3>

                    <div><p>Questo endpoint consente l&rsquo;autenticazione sia per utenti standard che per amministratori. Gli utenti possono inviare le proprie credenziali di accesso (email e password), e se sono corrette, l&rsquo;endpoint restituisce un token JWT. Il token permette l&rsquo;accesso alle risorse protette dell&rsquo;applicazione. Le autorizzazioni sono poi gestite in base al ruolo associato al token dell&rsquo;utente: &ldquo;USER&rdquo; per utenti standard e &ldquo;ADMIN&rdquo; per amministratori.EndFragment</p>
</div>

                    <div>
                        <ul class="nav nav-tabs" role="tablist">
                            <li role="presentation" class="active"><a href="#request-login-uente-e-admin-example-curl" data-toggle="tab">Curl</a></li>
                            <li role="presentation"><a href="#request-login-uente-e-admin-example-http" data-toggle="tab">HTTP</a></li>
                        </ul>
                        <div class="tab-content">
                            <div class="tab-pane active" id="request-login-uente-e-admin-example-curl">
                                <pre><code class="hljs curl">curl -X POST -d '{
    "email": "prova2@prova.it", 
    "password": "prova2" 
}
' "http://localhost:8081/auth/login"</code></pre>
                            </div>
                            <div class="tab-pane" id="request-login-uente-e-admin-example-http">
                                <pre><code class="hljs http">POST /auth/login HTTP/1.1
Host: localhost:8081

{
    "email": "prova2@prova.it", 
    "password": "prova2" 
}
</code></pre>
                            </div>
                        </div>
                    </div>

                    

                    <hr>
                </div>
                
                
                <div class="request">

                    <h3 id="request-nuovo-admin">
                        Nuovo Admin
                        <a href="#request-nuovo-admin"><i class="glyphicon glyphicon-link"></i></a>
                    </h3>

                    <div><p>Questo endpoint consente la creazione di un nuovo amministratore. Per accedervi, è necessario includere nel token di autenticazione (nella forma <code>Authorization: Bearer</code> ) un ruolo di &ldquo;ADMIN&rdquo;. Il sistema verifica che il ruolo sia &ldquo;ADMIN&rdquo; estraendolo direttamente dal token JWT. Se il ruolo non è presente o non corrisponde a &ldquo;ADMIN&rdquo;, l&rsquo;accesso sarà negato con un errore di autorizzazione(403)</p>
</div>

                    <div>
                        <ul class="nav nav-tabs" role="tablist">
                            <li role="presentation" class="active"><a href="#request-nuovo-admin-example-curl" data-toggle="tab">Curl</a></li>
                            <li role="presentation"><a href="#request-nuovo-admin-example-http" data-toggle="tab">HTTP</a></li>
                        </ul>
                        <div class="tab-content">
                            <div class="tab-pane active" id="request-nuovo-admin-example-curl">
                                <pre><code class="hljs curl">curl -X POST -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiQURNSU4iLCJzdWIiOiJhZG1pbkBwcm92YS5pdCIsImlhdCI6MTczMTIyOTIxMCwiZXhwIjoxNzMxMjMyODEwfQ.jmjAe2IhkUc4l65GXuWOj0l3xUgzU4aSecqIUqKQDng" -d '{
    "email": "nuovo_admin@esempio.com",
    "password": "passwordSicura",
    "fullName": "Nome Admin"
}
' "http://localhost:8081/auth/admin/signup"</code></pre>
                            </div>
                            <div class="tab-pane" id="request-nuovo-admin-example-http">
                                <pre><code class="hljs http">POST /auth/admin/signup HTTP/1.1
Host: localhost:8081
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiQURNSU4iLCJzdWIiOiJhZG1pbkBwcm92YS5pdCIsImlhdCI6MTczMTIyOTIxMCwiZXhwIjoxNzMxMjMyODEwfQ.jmjAe2IhkUc4l65GXuWOj0l3xUgzU4aSecqIUqKQDng

{
    "email": "nuovo_admin@esempio.com",
    "password": "passwordSicura",
    "fullName": "Nome Admin"
}
</code></pre>
                            </div>
                        </div>
                    </div>

                    

                    <hr>
                </div>
                
                
                <div class="request">

                    <h3 id="request-registrazione-user">
                        Registrazione User
                        <a href="#request-registrazione-user"><i class="glyphicon glyphicon-link"></i></a>
                    </h3>

                    <div><p>Questo endpoint consente agli utenti di registrarsi come utenti standard. Inviando le proprie informazioni (nome completo, email, e password), il sistema creerà un nuovo profilo utente con ruolo di default &ldquo;USER&rdquo;. Dopo la registrazione, l’utente potrà autenticarsi e accedere alle funzionalità dell’applicazione consentite agli utenti standard.EndFragment</p>
</div>

                    <div>
                        <ul class="nav nav-tabs" role="tablist">
                            <li role="presentation" class="active"><a href="#request-registrazione-user-example-curl" data-toggle="tab">Curl</a></li>
                            <li role="presentation"><a href="#request-registrazione-user-example-http" data-toggle="tab">HTTP</a></li>
                        </ul>
                        <div class="tab-content">
                            <div class="tab-pane active" id="request-registrazione-user-example-curl">
                                <pre><code class="hljs curl">curl -X POST -d '{
    "email": "prova2@prova.it",
    "password": "prova2",
    "fullName": "prova2 prova"
}' "http://localhost:8081/auth/signup"</code></pre>
                            </div>
                            <div class="tab-pane" id="request-registrazione-user-example-http">
                                <pre><code class="hljs http">POST /auth/signup HTTP/1.1
Host: localhost:8081

{
    "email": "prova2@prova.it",
    "password": "prova2",
    "fullName": "prova2 prova"
}</code></pre>
                            </div>
                        </div>
                    </div>

                    

                    <hr>
                </div>
                


                
            </div>
        </div>
    </div>
</div>

<script src="https://code.jquery.com/jquery-2.2.2.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js"></script>
<script>
    $(document).ready(function() {
        $("table:not(.table)").addClass('table table-bordered');
    });
</script>
</body>
</html>
