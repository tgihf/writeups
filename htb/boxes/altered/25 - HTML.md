## HTLM

```html
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-cache, private
Date: Wed, 07 Sep 2022 18:17:49 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6Im9UeWgwL3VYM0tRY2YrdGVmanBOVGc9PSIsInZhbHVlIjoid0xOajFjUkxVTXlZeWlpczNXUk1wVVpKWE9MNG1md3hwU3EzRmQzUFJtZGdEMjlKUGxqMEtnNDlqMDdwZGp5bXlzamJ0YW5rUmN5U0Q4R2sycUxGZC9xMmJFRGhWTTNuMHdUWi9rZGNDTm9JRS9YT05ubFB4R3lHMmh5RkNWSi8iLCJtYWMiOiIyZDc3YzUyOTRhMjA1YjFiOTI1ZTQ2MjA1N2FjYzcwNmQzODkyMjI0YWIyMGU5MWE3MWRiYWU5NmM5NTBhZDBkIiwidGFnIjoiIn0%3D; expires=Wed, 07-Sep-2022 20:17:49 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6InR2bFQwUFc1Sys1UFRvaC9BSzlhRUE9PSIsInZhbHVlIjoiMlA1V2pBSWt0REIwbmdtV0dNTFFoM0NyOUYvNVpERXF3emNHNnVpVXFDTEF4UHh3STRhYTdrNDdzbHFsc2wzNmNjK0gvbFhGZHRCZnJnNGRCdFBnRlJrNm1LY0l5VjNoNnZYL1NRY2hqNzZERFBsdEQ5Q3kzZHVNRXFaM016MlgiLCJtYWMiOiJmYzY1MzJmZmZiNDAzOGNlOTcxYmNlMjc5ZWY3YWY0ZDRmOGQxMGRhZDM2ZDIwOGRkNjhmM2I1OGMwODdkYzY4IiwidGFnIjoiIn0%3D; expires=Wed, 07-Sep-2022 20:17:49 GMT; Max-Age=7200; path=/; samesite=lax
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Content-Length: 13431

<!doctype html>
<!--[if lt IE 7]>      <html class="no-js lt-ie9 lt-ie8 lt-ie7" lang=""> <![endif]-->
<!--[if IE 7]>         <html class="no-js lt-ie9 lt-ie8" lang=""> <![endif]-->
<!--[if IE 8]>         <html class="no-js lt-ie9" lang=""> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang=""> <!--<![endif]-->
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>UHC March Finals</title>
    <meta name="description" content="UHC March Finals">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <link rel="apple-touch-icon" href="https://i.imgur.com/QRAUqs9.png">
    <link rel="shortcut icon" href="https://i.imgur.com/QRAUqs9.png">

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/normalize.css@8.0.0/normalize.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.1.3/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/lykmapipo/themify-icons@0.1.2/css/themify-icons.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/pixeden-stroke-7-icon@1.2.3/pe-icon-7-stroke/dist/pe-icon-7-stroke.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/flag-icon-css/3.2.0/css/flag-icon.min.css">
    <link rel="stylesheet" href="http://10.129.227.109/css/cs-skin-elastic.css">
    <link rel="stylesheet" href="http://10.129.227.109/css/style.css">
    <!-- <script type="text/javascript" src="https://cdn.jsdelivr.net/html5shiv/3.7.3/html5shiv.min.js"></script> -->
    <link href="https://cdn.jsdelivr.net/npm/chartist@0.11.0/dist/chartist.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/jqvmap@1.5.1/dist/jqvmap.min.css" rel="stylesheet">

    <link href="https://cdn.jsdelivr.net/npm/weathericons@2.1.0/css/weather-icons.css" rel="stylesheet" />
    <link href="https://cdn.jsdelivr.net/npm/fullcalendar@3.9.0/dist/fullcalendar.min.css" rel="stylesheet" />

   <style>
    #weatherWidget .currentDesc {
        color: #ffffff!important;
    }
        .traffic-chart {
            min-height: 335px;
        }
        #flotPie1  {
            height: 150px;
        }
        #flotPie1 td {
            padding:3px;
        }
        #flotPie1 table {
            top: 20px!important;
            right: -10px!important;
        }
        .chart-container {
            display: table;
            min-width: 270px ;
            text-align: left;
            padding-top: 10px;
            padding-bottom: 10px;
        }
        #flotLine5  {
             height: 105px;
        }

        #flotBarChart {
            height: 150px;
        }
        #cellPaiChart{
            height: 160px;
        }

    </style>
</head>

<body>

    <!-- Right Panel -->
        <!-- Header-->
        <header id="header" class="header">
            <div class="top-left">
                <div class="navbar-header">
                    <a class="navbar-brand" href="./"><h3>UHC Player Dashboard</h3></a>                    
                </div>
            </div>
        </header>


<script>
    function getBio(id,secret) {
        $.ajax({
            type: "GET",
            url: 'api/getprofile',
            data: {
                id: id,
                secret: secret
            },
            success: function(data)
            {
                document.getElementById('alert').style.visibility = 'visible';
                document.getElementById('alert').innerHTML = data;
            }

        });
    }

$(document).ready(function() {

    $('#GetBio').click(function(event){
        event.preventDefault();
        alert("tesT");
        $("#alert").html("data");
    });
  
  $('#loginform').submit(function() {

      $.ajax({
          type: "GET",
          url: 'api/getprofile',
          data: {
              password: $("#password").val()
          },
          success: function(data)
          {
            document.getElementById('alert').style.visibility = 'visible';
            document.getElementById('alert').innerHTML = data;
          }
      });     
      return false; 
  });
});
</script>
        <!-- Content -->
        <div class="content">
            <!-- Animated -->
            <div class="animated fadeIn">
                <div class="clearfix"></div>
                <!-- Orders -->
                <div class="orders">
                    <div class="row">
                        <div class="col-lg-12">
                            <div class="card">
                                <div class="card-body">
                                    <h4 class="box-title">UHC Player List</h4>
                                </div>
                                <p class="alert alert-info" id="alert" style="visibility: hidden;"></p>
                                <div class="card-body--">
                                    <div class="table-stats order-table ov-h">
                                        <table class="table ">
                                            <thead>
                                                <tr>
                                                    <th class="serial">#</th>
                                                   
                                                    <th>Name</th>
                                                    <th>Country</th>                                                    
                                                    <th>Profile</th>

                                                </tr>
                                            </thead>
                                            <tbody>
                                                                                            <tr>
                                                    <td class="serial">1</td>                                                   
                                                    <td><span class="name">big0us</span> </td>
                                                    <td><span class="country">Brazil</span> </td>                                          
                                                    <td><span class="profile"><a href="#" id="GetBio" onclick="getBio( '1', '89cb389c73f667c5511ce169033089cb' );">View</a> </span> </td>
                                                </tr>
                                                                                            <tr>
                                                    <td class="serial">2</td>                                                   
                                                    <td><span class="name">celesian</span> </td>
                                                    <td><span class="country">Brazil</span> </td>                                          
                                                    <td><span class="profile"><a href="#" id="GetBio" onclick="getBio( '2', 'c5169f4e0e83fd309f4d72a354021c60' );">View</a> </span> </td>
                                                </tr>
                                                                                            <tr>
                                                    <td class="serial">3</td>                                                   
                                                    <td><span class="name">luska</span> </td>
                                                    <td><span class="country">Brazil</span> </td>                                          
                                                    <td><span class="profile"><a href="#" id="GetBio" onclick="getBio( '3', '7d00387720025880db97c081f0a94b0f' );">View</a> </span> </td>
                                                </tr>
                                                                                            <tr>
                                                    <td class="serial">4</td>                                                   
                                                    <td><span class="name">tinyb0y</span> </td>
                                                    <td><span class="country">India</span> </td>                                          
                                                    <td><span class="profile"><a href="#" id="GetBio" onclick="getBio( '4', '856922e07b3b2975e84ab17af073dacf' );">View</a> </span> </td>
                                                </tr>
                                                                                            <tr>
                                                    <td class="serial">5</td>                                                   
                                                    <td><span class="name">o-tafe</span> </td>
                                                    <td><span class="country">England</span> </td>                                          
                                                    <td><span class="profile"><a href="#" id="GetBio" onclick="getBio( '5', '9429a100384a00549e5d6fcb9898ba46' );">View</a> </span> </td>
                                                </tr>
                                                                                            <tr>
                                                    <td class="serial">6</td>                                                   
                                                    <td><span class="name">watchdog</span> </td>
                                                    <td><span class="country">England</span> </td>                                          
                                                    <td><span class="profile"><a href="#" id="GetBio" onclick="getBio( '6', '7a5cd01cdb222330a1ec68b439887ea1' );">View</a> </span> </td>
                                                </tr>
                                                                                            <tr>
                                                    <td class="serial">7</td>                                                   
                                                    <td><span class="name">mydonut</span> </td>
                                                    <td><span class="country">Canada</span> </td>                                          
                                                    <td><span class="profile"><a href="#" id="GetBio" onclick="getBio( '7', '819be63ab512c4c2195f86f35f89b2d7' );">View</a> </span> </td>
                                                </tr>
                                                                                            <tr>
                                                    <td class="serial">8</td>                                                   
                                                    <td><span class="name">bee</span> </td>
                                                    <td><span class="country">Brazil</span> </td>                                          
                                                    <td><span class="profile"><a href="#" id="GetBio" onclick="getBio( '8', 'e27a91d74d9feb990bf6cb354de7a72d' );">View</a> </span> </td>
                                                </tr>
                                                                                            <tr>
                                                    <td class="serial">9</td>                                                   
                                                    <td><span class="name">admin</span> </td>
                                                    <td><span class="country">Unknown</span> </td>                                          
                                                    <td><span class="profile"><a href="#" id="GetBio" onclick="getBio( '9', 'd3e050b4b3e0e0e009ec7993adbcf58e' );">View</a> </span> </td>
                                                </tr>
                                                                                        </tbody>                                            
                                        </table>
                                    </div> 
                                </div>
                            </div>
                        </div> 
                </div>

            </div>
            <!-- .animated -->
        </div>
        <!-- /.content -->
        <div class="clearfix"></div>




<!-- Footer -->
        <footer class="site-footer">
            <div class="footer-inner bg-white">
                <div class="row">
                    <div class="col-sm-6">
                    </div>
                    <div class="col-sm-6 text-right">
                    </div>
                </div>
            </div>
        </footer>
        <!-- /.site-footer -->
    </div>
    <!-- /#right-panel -->

    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/jquery@2.2.4/dist/jquery.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.14.4/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.1.3/dist/js/bootstrap.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/jquery-match-height@0.7.2/dist/jquery.matchHeight.min.js"></script>

</body>
</html>

```
