import json
import argparse
import os
from collections import Counter
from urllib.parse import urlparse, urlunparse, unquote
import tiktoken
import yaml
import base64

enc = tiktoken.get_encoding("cl100k_base")


def count_tokens(text):
    tokens = enc.encode(text)
    return len(tokens)


def load_har_file(file_path):
    with open(file_path, 'r', encoding='utf-8-sig') as f:
        return json.load(f)


def remove_query_params(url):
    parsed_url = urlparse(url)
    clean_url = urlunparse(parsed_url._replace(query=""))
    return clean_url


def parse_multipart(data, boundary):
    boundary_delimiter = f'--{boundary}'
    parts = data.split(boundary_delimiter)

    parts = [part.strip() for part in parts if part.strip() and part.strip() != '--']
    parsed_parts = []

    for part in parts:
        key = part.split('\r\n\r\n')[0].split('; name="')[1][:-1]

        if len(part.split('\r\n\r\n')) == 2:
            value = part.split('\r\n\r\n')[1]
        else:
            value = None

        parsed_parts.append({key: value})

    return parsed_parts


def convert_headers(headers, exclude_standard_headers):
    standard_headers = ['host', 'content-length', 'content-type', 'user-agent', 'accept', 'connection']
    return [{header['name']: header['value']} for header in headers if header['name'].lower() != 'cookie' and (
            not exclude_standard_headers or header['name'].lower() not in standard_headers)]


def filter_entries(entries, exclude_static=True, exclude_cookies=False, exclude_standard_headers=False):
    filtered_entries = {}
    static_values = ['.css', '.js', '.png', '.svg', '.jpg', '.jpeg', '.gif', '.woff', '.woff2', '.ttf']

    for index, entry in enumerate(entries):
        request = entry['request']
        response = entry['response']

        if exclude_static:
            clean_url = remove_query_params(request['url'])
            if any(clean_url.endswith(ext) for ext in static_values):
                continue

        filtered_entry = {
            "request": {k: v for k, v in request.items() if k not in ['bodySize', 'headersSize', 'httpVersion']},
            "response": {k: v for k, v in response.items() if
                         k not in ['bodySize', 'headersSize', 'statusText', 'httpVersion']},
            "comment": entry.get('comment', '')
        }

        if 'cookies' in request and not exclude_cookies:
            filtered_entry['request']['cookies'] = [{cookie['name']: cookie['value']} for cookie in request['cookies']]
        else:
            del filtered_entry['request']['cookies']

        if 'cookies' in response and not exclude_cookies:
            filtered_entry['response']['cookies'] = [{cookie['name']: cookie['value']} for cookie in
                                                     response['cookies']]
        else:
            del filtered_entry['response']['cookies']

        if 'postData' in request:
            postData = request['postData']
            if 'mimeType' in postData and 'multipart' in postData['mimeType']:
                boundary_header = [header for header in request['headers'] if header['name'].lower() == 'content-type']
                boundary = boundary_header[0]['value'].split('boundary=')[1]
                filtered_entry['request']['postData'] = parse_multipart(postData.get('text', ''), boundary)
            else:
                postData_text = postData.get('text', '')
                filtered_entry['request']['postData'] = decode_data(postData_text)

        if 'queryString' in request:
            filtered_entry['request']['queryString'] = [{item['name']: unquote(item['value'])} for item in
                                                        request['queryString']]

        if 'headers' in request:
            filtered_entry['request']['headers'] = convert_headers(request['headers'], exclude_standard_headers)
        if 'headers' in response:
            filtered_entry['response']['headers'] = convert_headers(response['headers'], exclude_standard_headers)

        if 'content' in response:
            content = response['content']
            content_text = content.get('text', '')
            filtered_entry['response']['content'] = decode_data(content_text)

        filtered_entries[index] = filtered_entry

    return filtered_entries


def create_dict(entries, key, exclude_cookies):
    counter = Counter()
    for entry in entries.values():
        if key == 'cookies' and exclude_cookies:
            continue
        items = entry['request'].get(key, []) + entry['response'].get(key, [])
        for item in items:
            name = list(item.keys())[0]
            value = item[name]
            identifier = (name, value)
            counter[identifier] += 1

    frequent_items = {k: v for k, v in counter.items() if v > 2}

    dict_link = {}
    for index, value in enumerate(frequent_items):
        dict_link[index] = {value[0]: value[1]}

    return dict_link


def replace_items_with_references(entries, item_dict, key):
    item_to_index = {json.dumps(v): k for k, v in item_dict.items()}

    for entry_key, entry in entries.items():
        for side in ['request', 'response']:
            items = entry[side].get(key, [])
            new_items = []
            for item in items:
                item_string = json.dumps({k: v for k, v in item.items()})
                if item_string in item_to_index:
                    new_items.append(item_to_index[item_string])
                else:
                    new_items.append(item)
            entry[side][key] = new_items

    return entries


def minimize_json(data):
    return json.dumps(data, ensure_ascii=False, sort_keys=True)


def save_json_file(data, file_path):
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(data)


def save_yaml_file(data, file_path):
    with open(file_path, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=True)


def decode_data(data):
    try:
        return base64.b64decode(data).decode('utf-8')
    except (base64.binascii.Error, UnicodeDecodeError, ValueError):
        return unquote(data)


def process_har_file(file_path, exclude_static=True, exclude_cookies=False, exclude_standard_headers=False):
    har_data = load_har_file(file_path)
    entries = har_data['log']['entries']

    filtered_entries = filter_entries(entries, exclude_static=exclude_static, exclude_cookies=exclude_cookies,
                                      exclude_standard_headers=exclude_standard_headers)

    header_dict = create_dict(filtered_entries, 'headers', exclude_cookies=False)
    cookie_dict = create_dict(filtered_entries, 'cookies', exclude_cookies=exclude_cookies)

    minimized_entries = replace_items_with_references(filtered_entries, header_dict, 'headers')

    if not exclude_cookies:
        minimized_entries = replace_items_with_references(minimized_entries, cookie_dict, 'cookies')

    sorted_entries = {}

    for index, value in enumerate(minimized_entries, 1):
        sorted_entries[index] = minimized_entries[value]

    data = {
        "entries": sorted_entries,
        "header_dict": header_dict,
    }
    if not exclude_cookies:
        data["cookie_dict"] = cookie_dict

    return data


def get_requests_str_for_prompt(data):
    http_str = ''
    for key, value in data["entries"].items():
        if "comment" in value:
            http_str += f'{key}: {value["comment"]} {value["request"]["method"]} {value["request"]["url"]}'
        else:
            http_str += f'{key}: {value["request"]["method"]} {value["request"]["url"]}'

        http_str += os.linesep

    return http_str


def print_prompt(file_name, format_name, http_str):
    print(
        '''!!!IMPORTANT!!! You need to open attached file (''' + file_name + ''') and start analyzing it according to the description provided below !!!IMPORTANT!!! 
The file ''' + file_name + ''' attached contains optimized HTTP traffic data corresponding to a specific schema (see the "File Schema" section) and has a ''' + format_name + ''' structure obtained from a HAR file.

File Schema:
1. The keys header_dict and cookie_dict (cookie_dict may be absent) contain dictionaries (the structure for header_dict and cookie_dict is the same), where:
1.1 Key: a numerical ID, which serves as a reference that will be used by values from the keys headers and cookies (e.g., "1", "2", "3", etc.)
1.2 Value: a dictionary, where:
1.2.1 Key: the name of the header or cookie (e.g., "Content-Type", "User-Agent", "Set-Cookie")
1.2.2 Value: the value of the header or cookie (e.g., "application/json", "Mozilla/5.0", "sessionid=abc123")

2. The key entries contains dictionaries, where:
2.1 Key: the ordinal number of the request (e.g., "1", "2", "3", etc.)
2.2 Value: a dictionary with data on a specific HTTP request, including the following keys:
2.2.1 comment: comment on the request from the har file (may be absent)

2.2.2 request: a dictionary with request data, including the following keys:
2.2.2.1 method: HTTP method (e.g., "GET", "POST")
2.2.2.2 url: full URL (e.g., "https://example.com/api/resource")
2.2.2.3 queryString: query parameters sent in the URL (e.g., [{"name": "value"}, {"id": "123"}])
2.2.2.4 postData: data sent in the request body (can be an array of dictionaries if it is multiPart data, or a string if the body is text)
2.2.2.5 headers: array of request headers (if the value is an int, it refers to a header from the header_dict key; if it is a dictionary, the key is the header name, and the value is its value)
2.2.2.6 cookies: array of request cookies (values are similar to the headers key, except that references point to the cookie_dict key. the key may be absent)

2.2.3 response: response data, including the following keys:
2.2.3.1 redirectURL: redirect URL
2.2.3.2 status: response code (e.g., 200, 404)
2.2.3.3 content: response body
2.2.3.4 headers: array of response headers (value types are similar to the headers key from the request key)
2.2.3.5 cookies: array of response cookies (value types are similar to the cookies key from the request key. the key may be absent)

List of HTTP requests in the attached analyzed file (with comments, which may be absent) from the entries key:
''' + http_str + '''

You need to perform the following actions for successful analysis:
1. Analyze the file structure according to its schema (see the "File Schema" section) and memorize it (for simplification, a list of HTTP requests of this file is provided above).
2. From the analyzed file structure, analyze HTTP requests by the sent query parameters and body, identifying what needs to be correlated when creating load testing scripts (identifiers, dates, tokens, etc.) for software like JMeter\Gatling\HP Loadrunner, and which are likely static and do not require correlation (your task, in essence, will be analogous to the "autocorrelation" feature in HP Loadrunner VuGen).
2.1. Determine from which HTTP request responses the required data can be obtained.
2.2. Describe how these data can be extracted from there (e.g., using JsonPath or RegEx).
2.3. Note that correlated data may include dynamically generated identifiers, timestamps, and tokens that change with each request.

Examples of parameterizable data:
- Session identifiers such as "sessionid" or "cfids"
- Timestamps such as "Date" or "Expires"
- Tokens used for authorization or authentication
- ID parameters
- Certain numerical or symbolic parameters

File for analysis attached:
''' + file_name)


def main():
    parser = argparse.ArgumentParser(description='Process HAR file and minimize JSON/YAML.')
    parser.add_argument('--input', help='Input HAR file path')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--format', choices=['json', 'yaml'], default='json', help='Output file format')
    parser.add_argument('--no-static', action='store_true', help='Exclude static resources')
    parser.add_argument('--no-cookies', action='store_true', help='Exclude cookies')
    parser.add_argument('--no-standard-headers', action='store_true', help='Exclude standard headers')

    args = parser.parse_args()

    data = process_har_file(args.input, exclude_static=args.no_static, exclude_cookies=args.no_cookies,
                            exclude_standard_headers=args.no_standard_headers)

    http_str = get_requests_str_for_prompt(data)
    token_count_json = count_tokens(minimize_json(data))
    token_count_yaml = count_tokens(yaml.dump(data, allow_unicode=True))
    print(f"Total tokens in JSON format: {token_count_json}, in YAML format: {token_count_yaml}")

    if args.format == 'json':
        if not args.output.endswith('.json'):
            file_name = args.output + '.json'
        else:
            file_name = args.output

        minimized_data = minimize_json(data)

        print_prompt(file_name, args.format.upper(), http_str)
        save_json_file(minimized_data, file_name)
    elif args.format == 'yaml':
        if not args.output.endswith('.yaml'):
            file_name = args.output + '.yaml'
        else:
            file_name = args.output

        print_prompt(file_name, args.format.upper(), http_str)
        save_yaml_file(data, file_name)


if __name__ == '__main__':
    main()
