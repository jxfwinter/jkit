#ifndef RESTFUL_UTILITY_H
#define RESTFUL_UTILITY_H

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <cstdio>
#include <cctype>
#include <string>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>

inline bool case_insensitive_equal(const std::string &str1, const std::string &str2) noexcept {
    return str1.size() == str2.size() &&
            std::equal(str1.begin(), str1.end(), str2.begin(), [](char a, char b) {
        return tolower(a) == tolower(b);
    });
}
class CaseInsensitiveEqual {
public:
    bool operator()(const std::string &str1, const std::string &str2) const noexcept {
        return case_insensitive_equal(str1, str2);
    }
};
// Based on https://stackoverflow.com/questions/2590677/how-do-i-combine-hash-values-in-c0x/2595226#2595226
class CaseInsensitiveHash {
public:
    size_t operator()(const std::string &str) const noexcept {
        size_t h = 0;
        std::hash<int> hash;
        for(auto c : str)
            h ^= hash(tolower(c)) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

typedef std::unordered_multimap<std::string, std::string, CaseInsensitiveHash, CaseInsensitiveEqual> CaseInsensitiveMultimap;

/// Percent encoding and decoding
class Percent
{
public:
    /// Returns percent-encoded string
    static std::string encode(const std::string &value) noexcept {
        static auto hex_chars = "0123456789ABCDEF";

        std::string result;
        result.reserve(value.size()); // Minimum size of result

        for(auto &chr : value) {
            if(chr == ' ')
                result += '+';
            else if(chr == '!' || chr == '#' || chr == '$' || (chr >= '&' && chr <= ',') || (chr >= '/' && chr <= ';') || chr == '=' || chr == '?' || chr == '@' || chr == '[' || chr == ']')
                result += std::string("%") + hex_chars[chr >> 4] + hex_chars[chr & 15];
            else
                result += chr;
        }

        return result;
    }

    /// Returns percent-decoded string
    static std::string decode(const std::string &value) noexcept {
        std::string result;
        result.reserve(value.size() / 3 + (value.size() % 3)); // Minimum size of result

        for(std::size_t i = 0; i < value.size(); ++i) {
            auto &chr = value[i];
            if(chr == '%' && i + 2 < value.size()) {
                auto hex = value.substr(i + 1, 2);
                auto decoded_chr = static_cast<char>(std::strtol(hex.c_str(), nullptr, 16));
                result += decoded_chr;
                i += 2;
            }
            else if(chr == '+')
                result += ' ';
            else
                result += chr;
        }

        return result;
    }
};

namespace kkurl
{
//根据url后缀获取 content-type
inline boost::beast::string_view mime_type(boost::beast::string_view path)
{
    using boost::beast::iequals;
    auto const ext = [&path]
    {
        auto const pos = path.rfind(".");
        if(pos == boost::beast::string_view::npos)
            return boost::beast::string_view{};
        return path.substr(pos);
    }();
    if(iequals(ext, ".htm"))  return "text/html";
    if(iequals(ext, ".html")) return "text/html";
    if(iequals(ext, ".php"))  return "text/html";
    if(iequals(ext, ".css"))  return "text/css";
    if(iequals(ext, ".txt"))  return "text/plain";
    if(iequals(ext, ".js"))   return "application/javascript";
    if(iequals(ext, ".json")) return "application/json";
    if(iequals(ext, ".xml"))  return "application/xml";
    if(iequals(ext, ".swf"))  return "application/x-shockwave-flash";
    if(iequals(ext, ".flv"))  return "video/x-flv";
    if(iequals(ext, ".png"))  return "image/png";
    if(iequals(ext, ".jpe"))  return "image/jpeg";
    if(iequals(ext, ".jpeg")) return "image/jpeg";
    if(iequals(ext, ".jpg"))  return "image/jpeg";
    if(iequals(ext, ".gif"))  return "image/gif";
    if(iequals(ext, ".bmp"))  return "image/bmp";
    if(iequals(ext, ".ico"))  return "image/vnd.microsoft.icon";
    if(iequals(ext, ".tiff")) return "image/tiff";
    if(iequals(ext, ".tif"))  return "image/tiff";
    if(iequals(ext, ".svg"))  return "image/svg+xml";
    if(iequals(ext, ".svgz")) return "image/svg+xml";
    return "application/octet-stream";
}

//根据完整url获取 不带参数的url与参数字符串
inline bool parse_target(const boost::beast::string_view& target, std::string &path, std::string &query_string)
{
    size_t query_start = target.find('?');
    if(query_start != boost::beast::string_view::npos)
    {
        path = target.substr(0, query_start).to_string();
        query_string = target.substr(query_start + 1).to_string();
    }
    else
    {
        path = target.to_string();
    }
    return true;
}

//解析url中参数字符串
inline CaseInsensitiveMultimap parse_query_string(const std::string &query_string)
{
    CaseInsensitiveMultimap result;

    if(query_string.empty())
        return result;

    size_t name_pos = 0;
    size_t name_end_pos = -1;
    size_t value_pos = -1;
    for(size_t c = 0; c < query_string.size(); ++c) {
        if(query_string[c] == '&') {
            auto name = query_string.substr(name_pos, (name_end_pos == std::string::npos ? c : name_end_pos) - name_pos);
            if(!name.empty()) {
                auto value = value_pos == std::string::npos ? std::string() : query_string.substr(value_pos, c - value_pos);
                result.emplace(std::move(name), Percent::decode(value));
            }
            name_pos = c + 1;
            name_end_pos = -1;
            value_pos = -1;
        }
        else if(query_string[c] == '=') {
            name_end_pos = c;
            value_pos = c + 1;
        }
    }
    if(name_pos < query_string.size()) {
        auto name = query_string.substr(name_pos, name_end_pos - name_pos);
        if(!name.empty()) {
            auto value = value_pos >= query_string.size() ? std::string() : query_string.substr(value_pos);
            result.emplace(std::move(name), Percent::decode(value));
        }
    }

    return result;
}

} //namespace kkurl


#endif
