#include "json2sql.h"
#include <sstream>

using std::ostringstream;

namespace JsonSql
{
json::array select_not_in_array(const json::array& from_arr, const json::array& in_arr, const string& key)
{
    json::array res;;
    auto it = from_arr.begin();
    for(; it!= from_arr.end(); ++it)
    {
        const json::object& from_value = it->as_object();
        const json::value* from_v = from_value.if_contains(key);
        if(!from_v)
            continue;
        bool find = false;
        auto it_in = in_arr.begin();
        for(; it_in!= in_arr.end(); ++it_in)
        {
            const json::object& in_value = it_in->as_object();
            const json::value* in_v = in_value.if_contains(key);
            if(!in_v)
                continue;
            if(*from_v == *in_v)
            {
                find = true;
                break;
            }
        }
        if(!find)
        {
            res.push_back(*from_v);
        }
    }
    return std::move(res);
}

string value_to_sql_str(const json::value &v)
{
    ostringstream os;
    if (v.is_null())
    {
        os << "null";
    }
    else if (v.is_number() || v.is_bool())
    {
        os << json::serialize(v);
    }
    else if (v.is_string())
    {
        string tmp = json::serialize(v);
        tmp[0] = '\'';
        tmp[tmp.size() - 1] = '\'';
        os << tmp;
    }
    else if (v.is_array())
    {
        string tmp = json::serialize(v);
        tmp[0] = '{';
        tmp[tmp.size() - 1] = '}'; //[  ]换成大括号
        os << "'" << tmp << "'";
    }
    else if (v.is_structured())
    {
        os << "'" << json::serialize(v) << "'";
    }
    else
    {
        os << json::serialize(v);
    }
    return os.str();
}

string arr_to_sql_in_arr(const json::array &v)
{
    ostringstream os;
    os << json::serialize(v); //输出 [1, 3, 4]
    string str = os.str();
    str[0] = '(';
    str[str.size() - 1] = ')'; //[  ]换成sql 小括号
    boost::replace_all(str, "\"", "'");
    return str;
}

string comma_arr_to_sql_in_arr(const string &str, bool is_text)
{
    vector<string> arr;
    boost::split(arr, str, boost::is_any_of(" ,"), boost::token_compress_on);
    if(is_text)
    {
        for(string&s : arr)
        {
            s = "'" + s + "'";
        }
    }

    string in_arr = "(" + boost::join(arr, ",") + ")";
    return in_arr;
}

string obj_to_update_sql_str(const json::object &obj, const string &key_where, const string &value_where, const string &tbl_name)
{
    if (obj.empty())
    {
        return "";
    }
    ostringstream sql_text;
    sql_text << "update " << tbl_name << " set ";

    auto last = obj.end();
    --last;
    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        //if (it.key() != key_where)
        //{
            sql_text << it->key() << "=" << value_to_sql_str(it->value());
            if (it != last)
            {
                sql_text << ",";
            }
        //}
    }
    sql_text << " where " << key_where << "='" << value_where << "'";
    return sql_text.str();
}

string obj_to_update_sql_str(const json::object &obj, const map<string, string> &key_value_wheres, const string &tbl_name)
{
    if (obj.empty())
    {
        return "";
    }
    ostringstream sql_text;
    sql_text << "update " << tbl_name << " set ";
    auto last = obj.end();
    --last;
    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        sql_text << it->key() << "=" << value_to_sql_str(it->value());
        if (it != last)
        {
            sql_text << ",";
        }
    }
    sql_text << " where ";

    auto last_where = key_value_wheres.end();
    --last_where;
    for (auto it = key_value_wheres.begin(); it != key_value_wheres.end(); ++it)
    {
        sql_text << it->first << "='" << it->second << "'";
        if (it != last_where)
        {
            sql_text << " and ";
        }
    }
    return sql_text.str();
}

string obj_to_update_sql_str(const json::object &obj, const json::object &key_value_wheres, const string &tbl_name)
{
    if (obj.empty())
    {
        return "";
    }
    ostringstream sql_text;
    sql_text << "update " << tbl_name << " set ";
    auto last = obj.end();
    --last;
    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        sql_text << it->key() << "=" << value_to_sql_str(it->value());
        if (it != last)
        {
            sql_text << ",";
        }
    }
    sql_text << " where ";

    auto last_where = key_value_wheres.end();
    --last_where;
    for (auto it = key_value_wheres.begin(); it != key_value_wheres.end(); ++it)
    {
        sql_text << it->key() << "=" << value_to_sql_str(it->value());
        if (it != last_where)
        {
            sql_text << " and ";
        }
    }
    return sql_text.str();
}

string obj_to_insert_sql_str(const json::object &obj, const string &tbl_name)
{
    if (obj.empty())
    {
        return "";
    }

    ostringstream sql_text;
    sql_text << "insert into " << tbl_name << "(";
    auto last = obj.end();
    --last;

    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        sql_text << it->key();
        if (it != last)
        {
            sql_text << ",";
        }
    }

    sql_text << ") values(";
    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        sql_text << value_to_sql_str(it->value());
        if (it != last)
        {
            sql_text << ",";
        }
    }
    sql_text << ")";
    return sql_text.str();
}

string obj_to_upsert_update_sql_str(const json::object &obj, const string &key_where1,
                               const string &key_where2, const string &except_key, const string &tbl_name)
{
    if (obj.empty())
    {
        return "";
    }

    ostringstream sql_text;
    sql_text << "insert into " << tbl_name << "(";
    auto last = obj.end();
    --last;

    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        sql_text << it->key();
        if (it != last)
        {
            sql_text << ",";
        }
    }

    sql_text << ") values(";
    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        sql_text << value_to_sql_str(it->value());
        if (it != last)
        {
            sql_text << ",";
        }
    }

    json::object obj_cp = obj;
    obj_cp.erase(except_key);
    auto last_cp = obj_cp.end();
    --last_cp;

    sql_text << ") on conflict(" + key_where1 + "," + key_where2  + ") do update  set ";
    for(auto it = obj_cp.begin(); it != obj_cp.end(); ++it)
    {
        sql_text << it->key() << "=EXCLUDED." << it->key();
        if (it != last_cp)
        {
            sql_text << ",";
        }
    }

    return sql_text.str();
}

string obj_to_upsert_update_sql_str(const json::object &obj, const string &key_where1,
                               const string &key_where2, const string &key_where3, const string& except_key, const string &tbl_name)
{
    if (obj.empty())
    {
        return "";
    }

    ostringstream sql_text;
    sql_text << "insert into " << tbl_name << "(";
    auto last = obj.end();
    --last;

    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        sql_text << it->key();
        if (it != last)
        {
            sql_text << ",";
        }
    }

    sql_text << ") values(";
    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        sql_text << value_to_sql_str(it->value());
        if (it != last)
        {
            sql_text << ",";
        }
    }
    json::object obj_cp = obj;
    obj_cp.erase(except_key);
    auto last_cp = obj_cp.end();
    --last_cp;

    sql_text << ") on conflict(" + key_where1 + "," + key_where2  + "," + key_where3 + ") do update  set ";
    for(auto it = obj_cp.begin(); it != obj_cp.end(); ++it)
    {
        sql_text << it->key() << "=EXCLUDED." << it->key();
        if (it != last_cp)
        {
            sql_text << ",";
        }
    }

    return sql_text.str();
}

string obj_to_upsert_update_sql_str(const json::object &obj, const vector<string> &key_wheres, const string& except_key, const string &tbl_name)
{
    if (obj.empty())
    {
        return "";
    }

    ostringstream sql_text;
    sql_text << "insert into " << tbl_name << "(";
    auto last = obj.end();
    --last;

    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        sql_text << it->key();
        if (it != last)
        {
            sql_text << ",";
        }
    }

    sql_text << ") values(";
    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        sql_text << value_to_sql_str(it->value());
        if (it != last)
        {
            sql_text << ",";
        }
    }
    json::object obj_cp = obj;
    obj_cp.erase(except_key);
    auto last_cp = obj_cp.end();
    --last_cp;

    string key_arr;
    auto last_key = key_wheres.end();
    --last_key;
    for(auto it = key_wheres.begin(); it!=key_wheres.end(); ++it)
    {
        key_arr += *it;
        if(it != last_key)
        {
            key_arr += ",";
        }
    }

    sql_text << ") on conflict(" + key_arr + ") do update set ";
    for(auto it = obj_cp.begin(); it != obj_cp.end(); ++it)
    {
        sql_text << it->key() << "=EXCLUDED." << it->key();
        if (it != last_cp)
        {
            sql_text << ",";
        }
    }

    return sql_text.str();
}

string obj_to_upsert_nothing_sql_str(const json::object &obj, const vector<string> &key_wheres, const string &tbl_name)
{
    if (obj.empty())
    {
        return "";
    }

    ostringstream sql_text;
    sql_text << "insert into " << tbl_name << "(";
    auto last = obj.end();
    --last;

    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        sql_text << it->key();
        if (it != last)
        {
            sql_text << ",";
        }
    }

    sql_text << ") values(";
    for (auto it = obj.begin(); it != obj.end(); ++it)
    {
        sql_text << value_to_sql_str(it->value());
        if (it != last)
        {
            sql_text << ",";
        }
    }

    string key_arr;
    auto last_key = key_wheres.end();
    --last_key;
    for(auto it = key_wheres.begin(); it!=key_wheres.end(); ++it)
    {
        key_arr += *it;
        if(it != last_key)
        {
            key_arr += ",";
        }
    }

    sql_text << ") on conflict(" + key_arr + ") do nothing ";
    return sql_text.str();
}

void assign_json_value(json::object &assgin_json, const json::object &obj, const vector<string>& keys)
{
    for(const string& key : keys)
    {
        auto it = obj.find(key);
        if(it != obj.end())
        {
            assgin_json[key] = it->value();
        }
    }
}

}
