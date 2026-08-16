// Shinkuro vault backend: newline-delimited JSON-RPC over stdin/stdout.
//
// Methods:
//   ping                    -> {pong, open}
//   is_open                 -> {open}
//   create {path,password}  -> {open, path}
//   open   {path,password}  -> {open, path}
//   lock                    -> {open:false}
//   list                    -> {path, count, files:[{name,size,mtime}]}
//   add    {src}            -> {name,size,mtime}
//   extract{name}           -> {path,name,size}  (decrypted temp file)
//   delete {name}           -> {ok:true}
//   shutdown                -> {shutdown:true} then exits
//
// Every response is a single JSON line:
//   {"id":N,"ok":true,"result":{...}}
//   {"id":N,"ok":false,"error":{"code":"...","message":"..."}}
#include <iostream>
#include <string>

#include "crypto.hpp"
#include "json.hpp"
#include "util.hpp"
#include "vault.hpp"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

using namespace shinkuro;

static Vault g_vault;

static Json make_error(const std::string& code, const std::string& message) {
  Json e = Json::Object();
  e["code"] = code;
  e["message"] = message;
  return e;
}

// Executes one RPC method and returns its result (throws on failure).
static Json call(const std::string& method, const Json& params) {
  if (method == "ping") {
    Json r = Json::Object();
    r["pong"] = true;
    r["open"] = g_vault.is_open();
    return r;
  }
  if (method == "is_open") {
    Json r = Json::Object();
    r["open"] = g_vault.is_open();
    return r;
  }
  if (method == "create") {
    std::string path = params["path"].as_string();
    std::string password = params["password"].as_string();
    g_vault.create(to_path(path), password);
    secure_zero_string(password);
    Json r = Json::Object();
    r["open"] = true;
    r["path"] = path;
    return r;
  }
  if (method == "open") {
    std::string path = params["path"].as_string();
    std::string password = params["password"].as_string();
    g_vault.open(to_path(path), password);
    secure_zero_string(password);
    Json r = Json::Object();
    r["open"] = true;
    r["path"] = path;
    return r;
  }
  if (method == "lock") {
    g_vault.lock();
    Json r = Json::Object();
    r["open"] = false;
    return r;
  }
  if (method == "list") {
    return g_vault.list();
  }
  if (method == "add") {
    return g_vault.add(to_path(params["src"].as_string()));
  }
  if (method == "extract") {
    return g_vault.extract(params["name"].as_string());
  }
  if (method == "delete") {
    g_vault.remove(params["name"].as_string());
    Json r = Json::Object();
    r["ok"] = true;
    return r;
  }
  if (method == "shutdown") {
    g_vault.lock();
    Json r = Json::Object();
    r["shutdown"] = true;
    return r;
  }
  throw VaultError("INVALID", "未知方法: " + method);
}

int main() {
#ifdef _WIN32
  // Keep stdio binary so UTF-8 bytes and \n survive untouched.
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
#endif
  std::ios::sync_with_stdio(false);

  std::string line;
  while (std::getline(std::cin, line)) {
    if (line.empty()) continue;

    Json req;
    try {
      req = Json::parse(line);
    } catch (const std::exception&) {
      std::cout << Json(Json::Object{{"id", Json(nullptr)},
                                     {"ok", false},
                                     {"error", make_error("PARSE", "请求解析失败")}}).dump()
                << "\n"
                << std::flush;
      continue;
    }

    Json id = req.has("id") ? req["id"] : Json(nullptr);
    std::string method;
    Json params = Json::Object();
    try {
      method = req["method"].as_string();
      if (req.has("params")) params = req["params"];
    } catch (const std::exception& e) {
      std::cout << Json(Json::Object{{"id", id},
                                     {"ok", false},
                                     {"error", make_error("PARSE", e.what())}}).dump()
                << "\n"
                << std::flush;
      continue;
    }

    Json resp = Json::Object();
    resp["id"] = id;
    try {
      resp["ok"] = true;
      resp["result"] = call(method, params);
    } catch (const VaultError& ve) {
      resp["ok"] = false;
      resp["error"] = make_error(ve.code, ve.what());
    } catch (const AuthError& ae) {
      resp["ok"] = false;
      resp["error"] = make_error("CORRUPT", ae.what());
    } catch (const CryptoError& ce) {
      resp["ok"] = false;
      resp["error"] = make_error("CRYPTO_ERROR", ce.what());
    } catch (const std::exception& e) {
      resp["ok"] = false;
      resp["error"] = make_error("INTERNAL", e.what());
    }
    std::cout << resp.dump() << "\n" << std::flush;

    if (method == "shutdown") break;
  }

  g_vault.lock();
  return 0;
}
