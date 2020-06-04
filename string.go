// string
package sys

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

 
)

const (
	base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

var coder = base64.NewEncoding(base64Table)

//var XorKey []byte = []byte{0xB2, 0x09, 0xBB, 0x55, 0x93, 0x6D, 0x44, 0x47}

type Xor struct {
}
type m interface {
	enc(src string) string
	dec(src string) string
}

func (a *Xor) enc(src string, safecode string) string {
	var result string
	j := 0
	s := ""
	bt := []rune(src)
	XorKey := []byte(Substr(Md5(GetConfig("safecode", "default")+"chinatsm"+safecode), 0, 8))
	for i := 0; i < len(bt); i++ {
		s = strconv.FormatInt(int64(byte(bt[i])^XorKey[j]), 16)
		if len(s) == 1 {
			s = "0" + s
		}
		result = result + (s)
		j = (j + 1) % 8
	}
	//result = Base64Encode(result)
	return result
}

//生成Guid字串
func Guid() string {
	b := make([]byte, 48)

	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return Md5(base64.URLEncoding.EncodeToString(b))
}
 
func Md5(data string) string {
	md5Ctx := md5.New()                            //md5 init
	md5Ctx.Write([]byte(data))                     //md5 updata
	cipherStr := md5Ctx.Sum(nil)                   //md5 final
	encryptedData := hex.EncodeToString(cipherStr) //hex_digest
	return encryptedData
}
func Md5file(filename string) string {
	if Is_file(filename) == false {
		ShowErr("File not found", filename)
		return ""
	}
	file, inerr := os.Open(filename)
	if inerr == nil {
		md5h := md5.New()
		io.Copy(md5h, file)
		MD5Str := hex.EncodeToString(md5h.Sum(nil))
		file.Close()
		return MD5Str
	}
	file.Close()
	return ""
}
func (a *Xor) dec(src string, safecode string) string {
	var result string
	var s int64
	j := 0
	//src = Base64Decode(src)
	bt := []rune(src)
	XorKey := []byte(Substr(Md5(GetConfig("safecode", "default")+"chinatsm"+safecode), 0, 8))
	for i := 0; i < len(src)/2; i++ {
		s, _ = strconv.ParseInt(string(bt[i*2:i*2+2]), 16, 0)
		result = result + string(byte(s)^XorKey[j])
		j = (j + 1) % 8
	}
	return result
}
func Base64Encode(str string) string {
	src := []byte(str)
	return coder.EncodeToString(src)
}

func Base64Decode(str string) string {

	byteData, err := coder.DecodeString(string(str))
	if err != nil {
		return ""
	}
	return string(byteData[:])
}
func StrCode(str string, action string, safecode string) string { //加密解密字符串
	xor := Xor{}
	//fmt.Println(xor.enc("123fsgdg0fd"))
	//fmt.Println(xor.dec("833b8833e00a2020826fdf"))

	if action == "" || action == "ENCODE" {
		return xor.enc(str, safecode)
	} else {
		return xor.dec(str, safecode)
	}

}
func Of_index(slice string, needArr []string) int {
	for k, v := range needArr {
		if slice == v {
			return k
		}
	}
	return -1
}
func IsSet(key int, slice []string) bool {
	for k, _ := range slice {
		if k == key {
			return true
		}
	}
	return false
}
func Isset(key string, mapname map[string]string) bool {

	if _, ok := mapname[key]; ok {
		return true
	} else {
		return false
	}
}
func In_array(slice string, needArr []string) bool {
	for _, v := range needArr {
		if slice == v {
			return true
		}
	}
	return false
}
func In_arrayInt(slid int, needArr []int) bool {
	for _, v := range needArr {
		if slid == v {
			return true
		}
	}
	return false
}
func Array_merge(old, newdata map[string]string) map[string]string {
	if newdata == nil {
		return old
	}
	if old == nil {
		return newdata
	}
	for k, v := range newdata {
		old[k] = v
	}
	return old
}
func Unset(index int, slice []string) []string {
	var newslice []string
	for k, v := range slice {
		if k == index {
			continue
		}
		newslice = append(newslice, v)
	}
	return newslice
}
func UnsetMap(key string, mapname map[string]string) map[string]string {
	mk := make(map[string]string)
	for k, v := range mapname {
		if k == key {
			continue
		}
		mk[k] = v
	}
	return mk
}
func explode(s string, n int) []string {
	l := utf8.RuneCountInString(s)
	if n < 0 || n > l {
		n = l
	}
	a := make([]string, n)
	for i := 0; i < n-1; i++ {
		ch, size := utf8.DecodeRuneInString(s)
		a[i] = s[:size]
		s = s[size:]
		if ch == utf8.RuneError {
			a[i] = string(utf8.RuneError)
		}
	}
	if n > 0 {
		a[n-1] = s
	}
	return a
}
func Explode(s, sep string, ns ...int) []string {
	//return strings.Split(str, tag)0, -1

	length := len(ns)
	n := -1
	if length >= 1 {
		n = ns[0]
	}
	return strings.SplitN(sep, s, n)
}
func ConvertToString(src string, srcCode string, tagCode string) string {
	srcCoder := mahonia.NewDecoder(srcCode)
	srcResult := srcCoder.ConvertString(src)
	tagCoder := mahonia.NewDecoder(tagCode)
	_, cdata, _ := tagCoder.Translate([]byte(srcResult), true)
	result := string(cdata)
	return result
}
func Gbk2utf8(str string) string {
	return ConvertToString(str, "gbk", "utf-8")
}
func Utf82gbk(str string) string {
	return ConvertToString(str, "utf-8", "gbk")
}
func Url_encode(str string) string {
	return url.QueryEscape(str)
}
func Url_decode(str string) string {
	urlDecodeStr, _ := url.QueryUnescape(str)
	return urlDecodeStr
}

func ToUpper(str string) string {
	return strings.ToUpper(str)
}
func ToLower(str string) string {
	return strings.ToLower(str)
}
func Map_merge(a1 map[int]map[string]string, a2 map[int]map[string]string) map[int]map[string]string {
	length := len(a1)
	for _, v := range a2 {
		a1[length] = v
		length++
	}
	return a1
}
func Abs(i int) int {
	if i < 0 {
		i = i * -1
	}
	return i
}
func ImplodeMap(seq string, arr map[int]string) string {
	var data []string
	for _, v := range arr {
		data = append(data, v)
	}
	return strings.Join(data, seq)
}
func Implode(seq string, list interface{}) string {
	listValue := reflect.Indirect(reflect.ValueOf(list))

	if listValue.Kind() != reflect.Slice {
		return ""
	}
	count := listValue.Len()
	listStr := make([]string, 0, count)

	for i := 0; i < count; i++ {
		v := listValue.Index(i)
		if str, err := getValue(v); err == nil {
			listStr = append(listStr, str)
		}
	}
	return strings.Join(listStr, seq)
}

func getValue(value reflect.Value) (res string, err error) {
	switch value.Kind() {
	case reflect.Ptr:
		res, err = getValue(value.Elem())
	default:
		res = fmt.Sprint(value.Interface())
	}
	return
}

func Substr(source string, start int, number ...int) string {
	var r = []rune(source)
	length := len(r)
	end := length
	if len(number) > 0 {
		end = number[0]
		if end > length {
			end = length
		}
	}

	if start < 0 {
		start = length + start
		if start > length {
			start = length
		}
	}
	if end < 0 {
		end = length + end
	} else {
		end = start + end
		if end > length {
			end = length
		}
	}
	if start == 0 && end == length {
		return source
	}

	var substring = ""

	for i := start; i < end; i++ {
		substring += string(r[i])
	}

	return substring
}

func End(data []string) int {
	var last int = len(data) - 1

	return last
}

func Round(f float64, n int) float64 {
	floatStr := fmt.Sprintf("%."+strconv.Itoa(n)+"f", f)
	inst, _ := strconv.ParseFloat(floatStr, 64)
	return inst
}
func Float2Str(v float64) string { //float转string
	//s1 := strconv.FormatFloat(v, 'E', -1, 32)
	return strconv.FormatFloat(v, 'G', 64, 32)

}

//float32 转 String工具类，保留6位小数
func Float2str(input_num float32) string {
	// to convert a float number to a string
	return strconv.FormatFloat(float64(input_num), 'f', 6, 64)
}

func Str_replace(findstr string, replacestr string, str string, ns ...int) string {
	var n int = -1
	if len(ns) >= 1 {
		n = ns[0]
	}
	return strings.Replace(str, findstr, replacestr, n)
}
func Reg_replace(findstr string, replacestr string, str string) string {
	re, _ := regexp.Compile(findstr) //[^\x00-\xff]
	return re.ReplaceAllString(str, replacestr)
}
func Findstr(str, source string) bool {
	return (strings.Contains(source, str))
}
func Htmltrim(src string) string {
	//将HTML标签全转换成小写
	re, _ := regexp.Compile("\\<[\\S\\s]+?\\>")
	src = re.ReplaceAllStringFunc(src, strings.ToLower)
	//去除STYLE
	re, _ = regexp.Compile("\\<style[\\S\\s]+?\\</style\\>")
	src = re.ReplaceAllString(src, "")
	//去除SCRIPT
	re, _ = regexp.Compile("\\<script[\\S\\s]+?\\</script\\>")
	src = re.ReplaceAllString(src, "")
	//去除所有尖括号内的HTML代码，并换成换行符
	re, _ = regexp.Compile("\\<[\\S\\s]+?\\>")
	src = re.ReplaceAllString(src, "\n")
	//去除连续的换行符
	re, _ = regexp.Compile("\\s{2,}")
	src = re.ReplaceAllString(src, "\n")
	return strings.TrimSpace(src)
}

func MatchValue(source string, pattern string, ns ...int) string {
	if source == "" {
		return ""
	}
	arr := Match(source, pattern, ns...)
	value := ""
	for _, up := range arr {
		value = Trim(up[1])
	}
	return value
}
func Match(source string, pattern string, ns ...int) [][]string {
	var n int = -1
	if len(ns) > 0 {
		n = ns[0]
	}
	var reg *regexp.Regexp
	source = strings.Replace(source, "\n", " ", -1)
	reg = regexp.MustCompile(pattern)
	result := reg.FindAllStringSubmatch(source, n)
	return result
}
func Str2float(str string) float32 {
	f := Float(str)
	return float32(f)
}
func Float(str string) float64 {
	f, err := strconv.ParseFloat(str, 64)
	if err != nil {
		fmt.Println(f, err)
	}
	return f

}
func Float264(str string) float64 {
	f, err := strconv.ParseFloat(str, 32)
	if err != nil {
		fmt.Println(f, err)
	}
	return f

}
func LastStr(split string, str string) string {
	dot := []byte(split)
	if split == "" || str == "" {
		return ""
	}
	for i := len(str) - 1; i >= 0 && str[i] != '/'; i-- {
		if str[i] == dot[0] {
			return str[i:]
		}
	}
	return ""

}

/**
 * 字符串首字母转化为大写  bbbbbbbb ->  Bbbbbbbbb
 */
func StrFirstToUpper(str string) string {
	vv := []rune(str)
	var upperStr string
	for i := 0; i < len(vv); i++ {
		if i == 0 {
			upperStr += strings.ToUpper(string(vv[i])) // + string(vv[i+1])
		} else {
			upperStr += string(vv[i])
		}
	}

	return upperStr
}

func Intval(str string) int {
	if str == "" {
		return 0
	}
	//pat := "[0-9]+.[0-9]+" //正则

	pat := "[^0-9|^.|^-]"
	if ok, _ := regexp.Match(pat, []byte(str)); ok {
		fmt.Println(GetLine())
		fmt.Println("Abnormal character " + str)
	}
	re, _ := regexp.Compile(pat)
	//将匹配到的部分替换为""
	str = re.ReplaceAllString(str, "")
	if strings.Count(str, ".") >= 0 {
		arr := strings.Split(str, ".")
		str = arr[0]
	}
	if str == "" {
		return 0
	}
	i, err := strconv.Atoi(str)

	if err != nil {
		ShowErr(err, str)
	}

	return i

}
func Int642int(num int64) int {
	strtime := strconv.FormatInt(num, 10)
	intc, error := strconv.Atoi(strtime)
	if error != nil {
		ShowErr(error)
	}
	return intc
}
func Int2int64(num int) int64 {
	str := strconv.Itoa(num)
	int64, error := strconv.ParseInt(str, 10, 64)
	if error != nil {
		ShowErr(error)
	}
	return int64
}
func Int2str(num int) string {
	return strconv.Itoa(num)
}
func Int642str(num int64) string {
	return Int2str(Int642int(num))
}

func Int2float(num int) float64 {
	return Float264(Int2str(num))
}
func Ksort(data []string) []int {
	var keys []int
	for k := range data {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
func Sortk(data map[int]string) []int {
	var keys []int
	for k := range data {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
func Sortkk(data [][]string) []int {
	var keys []int
	for k := range data {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

/**
根据key排序
*/
type pairSort struct {
	Key   string
	Value int
}
type pairList []pairSort

func (p pairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p pairList) Len() int           { return len(p) }
func (p pairList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func Arrsort(mp []map[string]string, sortfield string) (newdata []map[string]string) {
	if len(sortfield) > 0 {
		fid := sortfield
		p := make(pairList, len(mp))

		for k, v := range mp {
			key := Int2str(k)
			p[k] = pairSort{key, Intval(v[fid])}
		}

		sort.Sort(p)

		for _, v := range p {
			key := Intval(v.Key)

			newdata = append(newdata, mp[key])
		}
		return
	} else {
		var newMp = make([]int, 0)
		for k, _ := range mp {
			newMp = append(newMp, k)
		}
		sort.Ints(newMp)
		for _, v := range newMp {
			newdata[v] = mp[v]
		}
	}
	return
}
func Mapsort(mp map[string]map[string]string, sortfield string) map[string]map[string]string {
	newdata := make(map[string]map[string]string)
	if len(sortfield) <= 0 {
		var newMp = make([]string, 0)
		for k, _ := range mp {
			newMp = append(newMp, k)
		}
		sort.Strings(newMp)

		for _, v := range newMp {
			newdata[v] = mp[v]
		}
		return newdata
	} else {
		fid := sortfield
		p := make(pairList, len(mp))
		i := 0
		for k, v := range mp {
			p[i] = pairSort{k, Intval(v[fid])}
			i++
		}
		sort.Sort(p)
		for _, v := range p {
			key := v.Key
			newdata[key] = mp[key]
		}
	}
	return newdata
}

type DataStrut struct {
	String            string
	MapIntString      map[int]string
	MapString         map[string]string
	MapStrStrstring   map[string]map[string]string
	Mapinterface      map[int]interface{}
	MapInterface      map[string]interface{}
	Interface         interface{}
	SliceStr          []string
	SliceInt          []int
	SliceInterface    []interface{}
	SliceMapInterface []map[string]interface{}
	SliceMapstring    []map[string]string
	SliceReflectValue []reflect.Value
	Int               int
	Int64             int64
	Bool              bool
	Float32           float32
	Float64           float64
	Pages             Page
}

func GetDatas(data interface{}) (result DataStrut) {

	//typ := reflect.TypeOf(data)
	//Log(typ.Name(), typ.Kind())
	switch vv := data.(type) {
	case interface{}:
		result.Interface = vv
	case map[int]string:
		result.MapIntString = vv
	case map[int]interface{}:
		result.Mapinterface = vv
	case map[string]interface{}:
		result.MapInterface = vv
	case map[string]string:
		result.MapString = vv
	case map[string]map[string]string:
		result.MapStrStrstring = vv
	case string:
		result.String = vv
	case int:
		result.Int = vv
	case int64:
		result.Int64 = vv
	case float32:
		result.Float32 = vv
	case float64:
		result.Float64 = vv
	case bool:
		result.Bool = vv
	case []string:
		result.SliceStr = vv
	case []int:
		result.SliceInt = vv
	case []map[string]interface{}:
		result.SliceMapInterface = vv
	case []map[string]string:
		result.SliceMapstring = vv
	case []interface{}:
		result.SliceInterface = vv
	case []reflect.Value:
	default:

		return result
	}
	return
}

func GetValue(value reflect.Value) (result DataStrut) {
	istype := value.Kind()
	Log(istype)
	switch istype {
	case reflect.String:
		result.String = value.String()
	case reflect.Bool:
		result.Bool = value.Bool()

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		result.Int64 = value.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		result.Int64 = value.Int()
	case reflect.Float32, reflect.Float64:
		result.Float64 = value.Float()
	case reflect.Interface, reflect.Ptr:
		result.Interface = value.Interface()
	case reflect.Map:
		result.SliceReflectValue = value.MapKeys()
	}
	return //reflect.DeepEqual(value.Interface(), reflect.Zero(value.Type()).Interface())
}
func GetData(data interface{}, node ...string) string {
	var returnstr string
	var key = ""
	if len(node) > 0 {
		key = node[0]
	}
	switch vv := data.(type) {
	case string:
		returnstr = vv
	case float64:
		returnstr = Float2Str(vv)
	case float32:
		returnstr = Float2str(vv)

	case int:
		returnstr = Int2str(vv)
	case bool:
		if vv == true {
			return "1"
		} else {
			return "0"
		}
	case []interface{}:
		returnstr = Json_encode(vv)
	case nil:
		return ""
	case map[string]interface{}:
		if key == "" {
			returnstr = Json_encode(vv)
		} else {
			return GetData(vv[key])
		}
	case map[string]string:
		if key == "" {
			returnstr = Json_encode(vv)
		} else {
			return GetData(vv[key])
		}
	case map[string]int:
		if key == "" {
			returnstr = Json_encode(vv)
		} else {
			return GetData(vv[key])
		}
	default:
		returnstr = Json_encode(vv)
		//fmt.Println(k, "is of a type I don't know how to handle ", fmt.Sprintf("%T", v))
	}
	return returnstr
}
func Xml2Arr(xmlfile string, rootstr ...string) []*Element {
	if Is_file(xmlfile) == false {
		return nil
	}
	doc := Xml(xmlfile)
	var rootdir string = "root"
	var groupdir string = "group"
	if len(rootstr) > 0 {
		rootdir = rootstr[0]
	}
	if len(rootstr) > 1 {
		groupdir = rootstr[1]
	}
	root := doc.Get(rootdir)
	groups := root.Data(groupdir)
	return groups
}
func Xml2arr(xmlfile string, rootstr ...string) map[string][]*Element {
	doc := Xml(xmlfile)
	if doc == nil {
		return nil
	}
	var rootdir string = "root"
	if len(rootstr) > 0 {
		rootdir = rootstr[0]
	}
	root := doc.Get(rootdir)
	groups := root.Datas()
	return groups
}
func Map2xml(data map[int]map[string]string, rootstr ...string) string {
	var rootdir string = "root"
	var groupdir string = "group"
	if len(rootstr) > 0 {
		rootdir = rootstr[0]
	}
	if len(rootstr) > 1 {
		groupdir = rootstr[1]
	}
	var xmlstr = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<" + rootdir + ">\n"

	for _, v := range data {
		xmlstr += "	<" + groupdir + ">\n"

		for key, val := range v {
			xmlstr += "		<" + key + ">" + val + "</" + key + ">\n"

		}
		xmlstr += "	</" + groupdir + ">\n"
	}
	xmlstr += "</" + rootdir + ">"
	return xmlstr
}
func Maps2Xml(data map[string]string, rootstr ...string) string {
	var rootdir string = ""
	var xmlstr = "\n"
	if len(rootstr) > 0 {
		xmlstr = ""
		rootdir = rootstr[0]
		xmlstr = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<" + rootdir + ">\n"
	}

	//var xmlstr = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<" + rootdir + ">\n"

	for k, v := range data {

		if k != "" {
			xmlstr += `		<` + k + `>` + v + `</` + k + `>` + "\n"
		} else {
			xmlstr += `		<attr>` + v + `</attr>` + "\n"
		}
	}

	if len(rootstr) > 0 {
		xmlstr += "\n</" + rootdir + ">"
	} else {
		xmlstr += `		`
	}
	return xmlstr
}
func Map2Xml(data map[string]map[string]string, rootstr ...string) string {
	var rootdir string = "root"

	if len(rootstr) > 0 {
		rootdir = rootstr[0]
	}

	var xmlstr = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<" + rootdir + ">\n"

	for k, v := range data {

		var astr string = ""
		var header string = "	<" + k + ">\n"
		for key, val := range v {
			if key != "" {
				astr += "		<" + key + ">" + val + "</" + key + ">\n"
			} else {
				header = "	<" + k + " name=\"" + val + "\">\n"
			}
		}
		xmlstr += header
		xmlstr += astr
		xmlstr += "	</" + k + ">\n"
	}
	xmlstr += "</" + rootdir + ">"
	return xmlstr
}
func QueryXml(file string, where string, selectedstr string, rootstr ...string) []map[string]string {
	xmldata := Xml2Arr(R_P+file, rootstr...)
	if selectedstr == "" {
		selectedstr = "id"
	}
	if xmldata == nil {
		return nil
	}

	var isid = true
	id := where
	qfield := "id"
	if where == "" || where == "0" {
		isid = false
	} else {
		whereArr := Explode(",", where)
		id = whereArr[0]
		if len(whereArr) > 1 {
			qfield = whereArr[1]
		}
	}

	selected := Explode(",", selectedstr)
	var retdata []map[string]string
	for _, v := range xmldata {
		xid := v.String(qfield)
		rdata := make(map[string]string)
		rdata[qfield] = xid

		for _, ename := range selected {
			if ename != qfield {
				rdata[ename] = HtmlDecode(v.String(ename))
			}
		}
		if isid {
			if rdata[qfield] == id {
				//var retdata []map[string]string
				retdata = append(retdata, rdata)
			}
		} else {
			retdata = append(retdata, rdata)
		}
	}
	return retdata
}
func DeleXml(xmlFile string, whereid string, fields string, rootstr ...string) bool {
	xmldata := Xml2Arr(R_P+xmlFile, rootstr...)
	field := Explode(",", fields)
	newdata := make(map[int]map[string]string)
	updateField := "id"
	arr := Explode(",", whereid)
	if len(arr) > 1 {
		updateField = arr[0]
		whereid = arr[1]
	}

	for k, v := range xmldata {

		rdata := make(map[string]string)

		for _, fid := range field {
			rdata[fid] = v.String(fid)
		}
		rdata[updateField] = v.String(updateField)
		if whereid == rdata[updateField] {
			continue
		} else {
			newdata[k] = rdata
		}
	}
	xmlstr := Map2xml(newdata, rootstr...)
	xmlfile := R_P + xmlFile
	if Write_file(xmlfile, xmlstr) {
		return true
	} else {
		return false
	}
}
func HtmlEncode(content string) string {
	//content = strings.Replace(content, " ", `&nbsp;`, -1)
	content = strings.Replace(content, `<`, `&lt;`, -1)
	content = strings.Replace(content, `>`, `&gt;`, -1)
	content = strings.Replace(content, `&`, `&amp;`, -1)
	content = strings.Replace(content, `"`, `&quot;`, -1)
	content = strings.Replace(content, `'`, `&apos;`, -1)
	content = strings.Replace(content, `×`, `&times;`, -1)
	content = strings.Replace(content, `÷`, `&divde;`, -1)
	return content
}
func HtmlDecode(content string) string {
	content = strings.Replace(content, `&nbsp;`, ` `, -1)
	content = strings.Replace(content, `&lt;`, `<`, -1)
	content = strings.Replace(content, `&gt;`, `>`, -1)
	content = strings.Replace(content, `&amp;`, `&`, -1)
	content = strings.Replace(content, `&quot;`, `"`, -1)
	content = strings.Replace(content, `&apos;`, `'`, -1)
	content = strings.Replace(content, `&times;`, `×`, -1)
	content = strings.Replace(content, `&divde;`, `÷`, -1)
	content = strings.Replace(content, "\\u003c", "<", -1)
	content = strings.Replace(content, "\\u003e", ">", -1)
	content = strings.Replace(content, "\\u0026", "&", -1)
	return content
}

/**
*保存XML
**/
func SaveToXml(data map[string]string, id string, file string, act string, rootstr ...string) int {

	xmldata := Xml2Arr(R_P+file, rootstr...)

	var isupdate = true
	if id == "" || id == "0" || xmldata == nil {
		isupdate = false
	}
	var i int = 0
	var newid int = 1
	newdata := make(map[int]map[string]string)
	for key, value := range data {
		data[key] = HtmlEncode(value)
	}
	if xmldata != nil {
		for k, v := range xmldata {
			i = k
			rdata := make(map[string]string)
			rdata["id"] = v.String("id")
			for ename, _ := range data {
				rdata[ename] = HtmlEncode(v.String(ename))
			}
			var currid int = Intval(rdata["id"])
			if currid >= newid {
				newid = currid + 1
			}
			if isupdate {
				if id == rdata["id"] {
					if act == "dele" {
						continue
					} else {
						newdata[i] = data
					}

				} else {
					newdata[i] = rdata
				}
			} else {
				newdata[i] = rdata
			}
			i++
		}
	}
	if isupdate == false {
		data["id"] = Int2str(newid)
		newdata[i] = data
	}
	xmlstr := Map2xml(newdata, rootstr...)
	xmlfile := R_P + file
	if Write_file(xmlfile, xmlstr) {
		if isupdate {
			return Intval(id)
		} else {
			return newid
		}
	} else {
		return 0
	}
}

/**
*查询一个
**/
func GetoneXml(file string, id string, selectedstr string, rootstr ...string) map[string]string {
	if id == "" || id == "0" {
		return nil
	}
	data := QueryXml(file, id, selectedstr, rootstr...)
	if data != nil {
		return data[0]
	} else {
		return nil
	}
}

/**
*查询全部xml
**/
func queryXml(file string, selectedstr string, rootstr ...string) []map[string]string {
	data := QueryXml(file, "", selectedstr, rootstr...)
	return data
}

func Data2map1(data map[string]string) (map1 string) {

	for _, v := range data {
		map1 = v
	}
	return
}
func Data2map2(data map[string]string) (map2 map[string]string) {
	map2 = make(map[string]string)

	for k, v := range data {
		arr := Explode("[", k)
		key := strings.Replace(arr[1], "]", "", 1)
		map2[key] = v
	}
	return
}
func Data2map3(data map[string]string) (map3 map[string]map[string]string) {
	map3 = make(map[string]map[string]string)
	for k, v := range data {
		arr := Explode("[", k)
		key := strings.Replace(arr[1], "]", "", 1)
		key2 := strings.Replace(arr[2], "]", "", 1)

		if map3[key] == nil {
			map3[key] = make(map[string]string)
		}

		map3[key][key2] = v
	}
	return
}
func Data2map4(data map[string]string) (map4 map[string]map[string]map[string]string) {
	map4 = make(map[string]map[string]map[string]string)
	for k, v := range data {
		arr := Explode("[", k)
		key := strings.Replace(arr[1], "]", "", 1)
		key2 := strings.Replace(arr[2], "]", "", 1)
		key3 := strings.Replace(arr[3], "]", "", 1)
		if map4[key] == nil {
			map4[key] = make(map[string]map[string]string)
		}
		if map4[key][key2] == nil {
			map4[key][key2] = make(map[string]string)
		}
		map4[key][key2][key3] = v
	}
	return
}
func Data2map5(data map[string]string) (map5 map[string]map[string]map[string]map[string]string) {
	map5 = make(map[string]map[string]map[string]map[string]string)
	for k, v := range data {
		arr := Explode("[", k)
		key := strings.Replace(arr[1], "]", "", 1)
		key2 := strings.Replace(arr[2], "]", "", 1)
		key3 := strings.Replace(arr[3], "]", "", 1)
		key4 := strings.Replace(arr[4], "]", "", 1)
		if map5[key] == nil {
			map5[key] = make(map[string]map[string]map[string]string)
		}
		if map5[key][key2] == nil {
			map5[key][key2] = make(map[string]map[string]string)
		}
		if map5[key][key2][key3] == nil {
			map5[key][key2][key3] = make(map[string]string)
		}
		map5[key][key2][key3][key4] = v
	}
	return
}
