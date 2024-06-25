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
    filtered_entries = []
    static_values = ['.css', '.js', '.png', '.svg', '.jpg', '.jpeg', '.gif', '.woff', '.woff2', '.ttf']
    for entry in entries:
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

        filtered_entries.append(filtered_entry)
    return filtered_entries


def create_dict(entries, key, exclude_cookies):
    counter = Counter()
    for entry in entries:
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

    for entry in entries:
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
    return json.dumps(data, ensure_ascii=False)


def save_json_file(data, file_path, prompt):
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(prompt + os.linesep)
        f.write(data)


def save_yaml_file(data, file_path, prompt):
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(prompt + os.linesep)
        yaml.dump(data, f, allow_unicode=True)


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

    data = {
        "entries": minimized_entries,
        "header_dict": header_dict,
    }
    if not exclude_cookies:
        data["cookie_dict"] = cookie_dict

    return data


def main():
    parser = argparse.ArgumentParser(description='Process HAR file and minimize JSON/YAML.')
    parser.add_argument('--input', help='Input HAR file path')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--format', choices=['json', 'yaml'], default='json', help='Output file format')
    parser.add_argument('--no-static', action='store_true', help='Exclude static resources')
    parser.add_argument('--no-cookies', action='store_true', help='Exclude cookies')
    parser.add_argument('--no-standard-headers', action='store_true', help='Exclude standard headers')

    args = parser.parse_args()

    data_with_prompt = process_har_file(args.input, exclude_static=args.no_static, exclude_cookies=args.no_cookies,
                                        exclude_standard_headers=args.no_standard_headers)

    token_count_json = count_tokens(minimize_json(data_with_prompt))
    token_count_yaml = count_tokens(yaml.dump(data_with_prompt, allow_unicode=True))
    print(f"Total tokens in JSON format: {token_count_json}, in YAML format: {token_count_yaml}")

    prompt = '''This JSON file contains HTTP request and response data extracted and processed from a HAR (HTTP Archive) file. The data has been meticulously filtered to exclude static resources (e.g., .css, .js files) and minimized for efficient processing. Common headers and cookies, occurring frequently across multiple requests and responses, are stored in separate dictionaries ('header_dict' and 'cookie_dict') with unique identifiers to reduce repetition. Each entry in this file includes both 'request' and 'response' objects.

### How to Analyze This File

1. **Understanding the Structure**:
   - **entries**: This array holds individual HTTP transactions. Each transaction has a 'request' and a 'response' object.
   - **header_dict**: A dictionary of frequently occurring headers, referenced by unique identifiers within the entries.
   - **cookie_dict**: A dictionary of frequently occurring cookies, referenced similarly (included only if cookies are not excluded during processing).

2. **Components of Each Entry**:
   - **request**: Contains details about the HTTP request, including the method, URL, headers, cookies (if included), and postData (if available).
   - **response**: Contains details about the HTTP response, including the status, headers, cookies (if included), and content.
   - **postData**: If present in the request, it includes both the original and decoded data, which might be in URL-encoded or base64 format.

3. **Interpreting Headers and Cookies**:
   - Headers and cookies that appear frequently across requests and responses are referenced by identifiers (e.g., `1`, `2`) within the `header_dict` and `cookie_dict`. These references reduce redundancy and make the file more compact.
   - To understand the actual values of these referenced headers and cookies, look up the identifier in the corresponding dictionary.

### Steps for Detailed Analysis:

1. **Correlation and Pagination Analysis**:
   - **Correlation Analysis**: Identify patterns and relationships between different parameters and values in requests and responses. For instance, correlate query parameters with response statuses or content lengths.
   - **Pagination Analysis**: Determine how pagination parameters (e.g., `page`, `limit`) are used in requests and how they affect the responses.

2. **Extraction and Replacement Using jsonPath and RegEx**:
   - **jsonPath**: Utilize jsonPath expressions to precisely extract specific parameters and their values from the JSON structure.
   - **RegEx**: Use regular expressions to match patterns in the data, especially useful for dynamically generated values or complex query parameters.
   
### Examples:

1. **Finding Query Parameters**:
   - Use jsonPath: `$.entries[*].request.queryString[*]`
   - Use RegEx: `\"queryString\": \[\{.*?\}\]`

2. **Extracting Specific Headers**:
   - Use jsonPath to find a specific header (e.g., `Content-Type`): `$.entries[*].request.headers[?(@.name == 'Content-Type')].value`
   - Use RegEx to match headers: `\"headers\": \[\{.*?\"name\": \"Content-Type\".*?\}\]`

3. **Analyzing Pagination**:
   - jsonPath for pagination parameters: `$.entries[*].request.queryString[?(@.name == 'page' || @.name == 'limit')].value`
   - RegEx to match pagination: `\"queryString\": \[\{.*?\"name\": \"(page|limit)\".*?\}\]`

4. **Correlating Data**:
   - Find requests with specific response statuses: `$.entries[?(@.response.status == 200)].request.url`
   - Correlate request methods with response times: `$.entries[*].{method: request.method, time: response.time}`

### Example Workflow:

1. **Identify frequently used headers and cookies**:
   - Look up identifiers in `header_dict` and `cookie_dict`.

2. **Extract specific values for analysis**:
   - Use jsonPath or RegEx to extract parameters of interest.

3. **Correlate extracted values**:
   - Analyze patterns and relationships between different parameters and their effects on responses.

By following these steps, you can systematically analyze the processed HAR file, uncovering valuable insights about the HTTP transactions, and effectively extract and manipulate the necessary parameters using jsonPath and RegEx.

'''

    file_name = ''
    if args.format == 'json':
        if not args.output.endswith('.json'):
            file_name = args.output + '.json'
        else:
            file_name = args.output

        minimized_data = minimize_json(data_with_prompt)
        save_json_file(minimized_data, file_name, prompt)
    elif args.format == 'yaml':
        if not args.output.endswith('.yaml'):
            file_name = args.output + '.yaml'
        else:
            file_name = args.output

        save_yaml_file(data_with_prompt, file_name, prompt)


if __name__ == '__main__':
    main()
