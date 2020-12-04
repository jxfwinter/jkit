#ifndef JSON2SQL_H
#define JSON2SQL_H

#include <string>
#include <vector>
#include <map>
#include <boost/json.hpp>
#include <boost/algorithm/string.hpp>

namespace json = boost::json;
using std::string;
using std::vector;
using std::map;

namespace JsonSql
{
//from_arr数组中每个obj的key的值, 如果在in_arr中所有obj中key的值集合中不存在,就放入返回数组中
json::array select_not_in_array(const json::array& from_arr, const json::array& in_arr, const string& key);

//json value生成sql值
/*
 * "aaa" 输出  'aaa'
 * 4 输出 4
*/
string value_to_sql_str(const json::value &v);

//json数组转为 in 需要的 数组字符串
/*
 * [1, 3, 4] 输出 (1,3,4)
 * ["a", "b", "c"] 输出 ('a','b','c')
 *
 *
*/
string arr_to_sql_in_arr(const json::array &v);

//字符串根据is_text转为 sql中 所需要的in 需要的 数组
/*
 * 1,2,3 输出 (1,2,3)
 * aa,bb,cc 输出 ('aa', 'bb', 'cc')
 *
 *
*/
string comma_arr_to_sql_in_arr(const string &str, bool is_text);

//构造update sql语句
/*
 *  根据key_where字段名值value_where作为条件,构建update语句,条件值为字符串类型,构造的sql语句中会有单引号
 *  key_value_wheres 表示有多个条件,以 and连接,条件值为字符串类型,会被加引号,构造的sql语句中会有单引号
 *  obj为要更新的字段
 *
*/

string obj_to_update_sql_str(const json::object &obj, const string &key_where, const string &value_where, const string &tbl_name);

string obj_to_update_sql_str(const json::object &obj, const map<string, string>& key_value_wheres, const string &tbl_name);

//构造update sql语句
/*
 *  key_value_wheres 表示有多个条件的键值对,以 and连接,条件值为根据类型决定构造的sql语句中是否有单引号
 *  obj为要更新的字段
 *
*/

string obj_to_update_sql_str(const json::object &obj, const json::object& key_value_wheres, const string &tbl_name);

//构造insert sql语句
string obj_to_insert_sql_str(const json::object &obj, const string &tbl_name);

//构造conflict sql语句,如果冲突则更新
//key_where1 key_where2为冲突字段组合
string obj_to_upsert_update_sql_str(const json::object &obj, const string &key_where1,
                               const string &key_where2, const string& except_key, const string &tbl_name);

//构造conflict sql语句,如果冲突则更新
//key_where1 key_where2 key_where3为冲突字段组合
string obj_to_upsert_update_sql_str(const json::object &obj, const string &key_where1,
                               const string &key_where2, const string &key_where3, const string& except_key, const string &tbl_name);

//构造conflict sql语句,如果冲突则更新
//key_wheres为冲突字段组合
string obj_to_upsert_update_sql_str(const json::object &obj, const vector<string> &key_wheres, const string& except_key, const string &tbl_name);


//构造conflict sql语句,如果冲突,不更新
//key_wheres为冲突字段组合
string obj_to_upsert_nothing_sql_str(const json::object &obj, const vector<string> &key_wheres, const string &tbl_name);

//将obj中的key value赋值给assgin_json, 如果obj中存在
void assign_json_value(json::object& assgin_json, const json::object& obj, const vector<string>& keys);
}

#endif //JSON2SQL_H
