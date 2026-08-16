// Minimal, dependency-free JSON value + parser + serializer.
// Enough for the Shinkuro vault backend RPC protocol.
// UTF-8 is passed through verbatim; \uXXXX escapes are decoded to UTF-8.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace shinkuro {

class Json {
public:
  using Array = std::vector<Json>;
  using Object = std::map<std::string, Json>;
  using Variant =
      std::variant<std::nullptr_t, bool, int64_t, double, std::string, Array, Object>;

  Json() : v_(nullptr) {}
  Json(std::nullptr_t) : v_(nullptr) {}
  Json(bool b) : v_(b) {}
  Json(int i) : v_(static_cast<int64_t>(i)) {}
  Json(unsigned u) : v_(static_cast<int64_t>(u)) {}
  Json(int64_t i) : v_(i) {}
  Json(uint64_t i) : v_(static_cast<int64_t>(i)) {}
  Json(double d) : v_(d) {}
  Json(const char* s) : v_(std::string(s)) {}
  Json(std::string s) : v_(std::move(s)) {}
  Json(Array a) : v_(std::move(a)) {}
  Json(Object o) : v_(std::move(o)) {}

  // ---- type checks ----
  bool is_null() const { return std::holds_alternative<std::nullptr_t>(v_); }
  bool is_bool() const { return std::holds_alternative<bool>(v_); }
  bool is_int() const { return std::holds_alternative<int64_t>(v_); }
  bool is_double() const { return std::holds_alternative<double>(v_); }
  bool is_number() const { return is_int() || is_double(); }
  bool is_string() const { return std::holds_alternative<std::string>(v_); }
  bool is_array() const { return std::holds_alternative<Array>(v_); }
  bool is_object() const { return std::holds_alternative<Object>(v_); }

  // ---- accessors ----
  bool as_bool() const { return get<bool>("bool"); }
  int64_t as_int() const {
    if (is_int()) return std::get<int64_t>(v_);
    if (is_double()) return static_cast<int64_t>(std::get<double>(v_));
    fail("int");
    return 0;
  }
  double as_double() const {
    if (is_double()) return std::get<double>(v_);
    if (is_int()) return static_cast<double>(std::get<int64_t>(v_));
    fail("double");
    return 0;
  }
  const std::string& as_string() const { return get<std::string>("string"); }
  const Array& as_array() const { return get<Array>("array"); }
  const Object& as_object() const { return get<Object>("object"); }

  bool has(const std::string& key) const {
    if (!is_object()) return false;
    return std::get<Object>(v_).count(key) != 0;
  }

  // object access (mutating: inserts null when missing)
  Json& operator[](const std::string& key) {
    if (!is_object()) fail("object");
    auto& o = std::get<Object>(v_);
    auto it = o.find(key);
    if (it == o.end()) {
      auto [ins, _] = o.emplace(key, Json());
      return ins->second;
    }
    return it->second;
  }
  // object access (const: throws when missing)
  const Json& operator[](const std::string& key) const {
    if (!is_object()) fail("object");
    const auto& o = std::get<Object>(v_);
    auto it = o.find(key);
    if (it == o.end()) throw std::runtime_error("json: missing key '" + key + "'");
    return it->second;
  }
  // array access
  Json& operator[](size_t i) {
    if (!is_array()) fail("array");
    auto& a = std::get<Array>(v_);
    if (i >= a.size()) throw std::runtime_error("json: array index out of range");
    return a[i];
  }
  const Json& operator[](size_t i) const {
    if (!is_array()) fail("array");
    const auto& a = std::get<Array>(v_);
    if (i >= a.size()) throw std::runtime_error("json: array index out of range");
    return a[i];
  }

  size_t size() const {
    if (is_array()) return std::get<Array>(v_).size();
    if (is_object()) return std::get<Object>(v_).size();
    return 0;
  }

  void push_back(const Json& v) {
    if (!is_array()) fail("array");
    std::get<Array>(v_).push_back(v);
  }
  void push_back(Json&& v) {
    if (!is_array()) fail("array");
    std::get<Array>(v_).push_back(std::move(v));
  }

  std::string dump() const { return dump_value(v_); }

  static Json parse(const std::string& text) {
    Parser p(text);
    Json v = p.parse_value();
    p.skip_ws();
    if (!p.at_end()) p.err("trailing characters");
    return v;
  }

private:
  Variant v_;

  template <typename T>
  const T& get(const char* what) const {
    if (!std::holds_alternative<T>(v_)) fail(what);
    return std::get<T>(v_);
  }
  [[noreturn]] void fail(const char* what) const {
    throw std::runtime_error(std::string("json: not a ") + what);
  }

  // ------------------------- serialization -------------------------
  static std::string dump_value(const Variant& v) {
    if (std::holds_alternative<std::nullptr_t>(v)) return "null";
    if (std::holds_alternative<bool>(v)) return std::get<bool>(v) ? "true" : "false";
    if (std::holds_alternative<int64_t>(v)) return std::to_string(std::get<int64_t>(v));
    if (std::holds_alternative<double>(v)) return dump_double(std::get<double>(v));
    if (std::holds_alternative<std::string>(v)) return dump_string(std::get<std::string>(v));
    if (std::holds_alternative<Array>(v)) {
      std::string out = "[";
      const auto& a = std::get<Array>(v);
      for (size_t i = 0; i < a.size(); i++) {
        if (i) out += ",";
        out += dump_value(a[i].v_);
      }
      out += "]";
      return out;
    }
    // object
    std::string out = "{";
    const auto& o = std::get<Object>(v);
    bool first = true;
    for (const auto& [k, val] : o) {
      if (!first) out += ",";
      first = false;
      out += dump_string(k);
      out += ":";
      out += dump_value(val.v_);
    }
    out += "}";
    return out;
  }

  static std::string dump_double(double d) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.17g", d);
    return std::string(buf);
  }

  static std::string dump_string(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
      switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
          if (c < 0x20) {
            char esc[8];
            std::snprintf(esc, sizeof(esc), "\\u%04x", c);
            out += esc;
          } else {
            out += static_cast<char>(c);
          }
      }
    }
    out += "\"";
    return out;
  }

  // --------------------------- parsing ---------------------------
  struct Parser {
    const std::string& s;
    size_t i = 0;

    explicit Parser(const std::string& text) : s(text) {}

    [[noreturn]] void err(const std::string& msg) const {
      throw std::runtime_error("json: " + msg + " at byte " + std::to_string(i));
    }
    bool at_end() const { return i >= s.size(); }
    void skip_ws() {
      while (i < s.size()) {
        char c = s[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++;
        else break;
      }
    }
    char peek() {
      skip_ws();
      if (at_end()) err("unexpected end");
      return s[i];
    }
    char take() {
      skip_ws();
      if (at_end()) err("unexpected end");
      return s[i++];
    }
    void expect(char c) {
      if (take() != c) err(std::string("expected '") + c + "'");
    }

    Json parse_value() {
      char c = peek();
      if (c == '{') return parse_object();
      if (c == '[') return parse_array();
      if (c == '"') return Json(parse_string());
      if (c == 't') { consume_literal("true"); return Json(true); }
      if (c == 'f') { consume_literal("false"); return Json(false); }
      if (c == 'n') { consume_literal("null"); return Json(nullptr); }
      return parse_number();
    }

    void consume_literal(const char* lit) {
      for (const char* p = lit; *p; p++) {
        if (at_end() || s[i] != *p) err("invalid literal");
        i++;
      }
    }

    Json parse_object() {
      expect('{');
      Object o;
      skip_ws();
      if (peek() == '}') { i++; return Json(std::move(o)); }
      while (true) {
        skip_ws();
        if (at_end() || s[i] != '"') err("expected string key");
        std::string key = parse_string();
        expect(':');
        Json val = parse_value();
        o[key] = std::move(val);
        skip_ws();
        char c = take();
        if (c == '}') break;
        if (c != ',') err("expected ',' or '}'");
      }
      return Json(std::move(o));
    }

    Json parse_array() {
      expect('[');
      Array a;
      skip_ws();
      if (peek() == ']') { i++; return Json(std::move(a)); }
      while (true) {
        a.push_back(parse_value());
        skip_ws();
        char c = take();
        if (c == ']') break;
        if (c != ',') err("expected ',' or ']'");
      }
      return Json(std::move(a));
    }

    std::string parse_string() {
      expect('"');
      std::string out;
      while (true) {
        if (at_end()) err("unterminated string");
        unsigned char c = static_cast<unsigned char>(s[i++]);
        if (c == '"') break;
        if (c == '\\') {
          if (at_end()) err("bad escape");
          char e = s[i++];
          switch (e) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
              uint32_t cp = parse_hex4();
              if (cp >= 0xD800 && cp <= 0xDBFF) {
                // possible surrogate pair
                if (i + 1 < s.size() && s[i] == '\\' && s[i + 1] == 'u') {
                  size_t save = i;
                  i += 2;
                  uint32_t lo = parse_hex4();
                  if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                  } else {
                    i = save;  // not a pair; treat high surrogate as invalid
                    cp = 0xFFFD;
                  }
                } else {
                  cp = 0xFFFD;
                }
              } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                cp = 0xFFFD;
              }
              append_utf8(out, cp);
              break;
            }
            default: err("invalid escape");
          }
        } else {
          out += static_cast<char>(c);
        }
      }
      return out;
    }

    uint32_t parse_hex4() {
      if (i + 4 > s.size()) err("bad \\u escape");
      uint32_t v = 0;
      for (int k = 0; k < 4; k++) {
        char c = s[i++];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (c - '0');
        else if (c >= 'a' && c <= 'f') v |= (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (c - 'A' + 10);
        else err("bad hex digit");
      }
      return v;
    }

    static void append_utf8(std::string& out, uint32_t cp) {
      if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) cp = 0xFFFD;
      if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
      } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
      } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
      } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
      }
    }

    Json parse_number() {
      size_t start = i;
      if (i < s.size() && (s[i] == '-' || s[i] == '+')) i++;
      bool is_double = false;
      while (i < s.size()) {
        char c = s[i];
        if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
          if (c == '.' || c == 'e' || c == 'E') is_double = true;
          i++;
        } else {
          break;
        }
      }
      if (i == start) err("expected number");
      std::string num = s.substr(start, i - start);
      if (is_double) {
        return Json(std::strtod(num.c_str(), nullptr));
      }
      errno = 0;
      char* end = nullptr;
      long long iv = std::strtoll(num.c_str(), &end, 10);
      if (end == num.c_str()) err("bad number");
      return Json(static_cast<int64_t>(iv));
    }
  };
};

}  // namespace shinkuro
