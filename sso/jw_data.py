import json

from lxml import html

days = {
    '星期一': 1,
    '星期二': 2,
    '星期三': 3,
    '星期四': 4,
    '星期五': 5,
    '星期六': 6,
    '星期日': 7,
}

periods = {
    '第一大节': [1, 2],
    '第二大节': [3, 4],
    '第三大节': [5, 6],
    '第四大节': [7, 8],
    '第五大节': [9, 10],
    '第六大节': [11],
}

period_times = {
    '1-s': '08:00',
    '1-e': '08:45',

    '2-s': '09:00',
    '2-e': '09:45',

    '3-s': '10:00',
    '3-e': '10:45',

    '4-s': '10:55',
    '4-e': '11:40',


    '5-s': '14:00',
    '5-e': '14:45',

    '6-s': '14:50',
    '6-e': '15:35',

    '7-s': '15:55',
    '7-e': '16:40',

    '8-s': '16:45',
    '8-e': '17:30',


    '9-s': '18:50',
    '9-e': '19:35',

    '10-s': '19:45',
    '10-e': '20:30',

    '11-s': '20:40',
    '11-e': '21:25',
}


def process_course(div):
    courses = []
    course = {}
    for node in div.iter():
        text = (node.text.strip() if node.text else (node.tail.strip() if node.tail else '')).replace('&nbsp;', '').replace('&nbsp', '')
        if not text:
            continue
        title = node.attrib.get('title', '')
        if text == '---------------------': # 多个课程
            if course:
                courses.append(course)
                course = {}
            continue
        elif text == 'P' or text == 'O': # 调课
            course['adjust_course'] = True
            course['adjust_course_type'] = text
            continue

        if title == '老师':
            course['teacher'] = text
        elif title == '周次(节次)':
            week = []
            for week_str in text.split('(')[0].split(','):
                week_str = week_str.strip()
                if '-' in week_str:
                    start, end = week_str.split('-')
                    start = int(start)
                    end = int(end)
                    week.extend(range(start, end + 1))
                else:
                    week.append(int(week_str))
            course['weeks'] = week
        elif title == '教室':
            course['location'] = text
        else:
            course['courseName'] = text

    if course:
        courses.append(course)

    return courses

def get_timetable(content):
    hl = html.fromstring(content)

    semester = hl.xpath('//select[@id="xnxq01id"]/option[@selected]')[0].get('value') # 学期

    root = hl.xpath('//table[@id="kbtable"]')[0] # 课程表
    x = root.xpath('//tr[1]/th') # 星期
    row = []
    for day in x:
        x_str = day.text_content().strip()
        if x_str:
            row.append(x_str)

    y = root.xpath('//tr[position() > 1]/th') # 节
    col = []
    for period in y:
        x_str = period.text_content().strip()
        if x_str:
            col.append(x_str)

    data = {}
    for i in range(2, len(col) + 1): # 根据节获取每行课程
        col_key = col[i - 2]
        data[col_key] = []
        keys = root.xpath(f'//tr[{i}]/td/input[@name="jx0415zbdiv_2"]')
        for key in keys:
            data[col_key].append(root.xpath(f'//tr[{i}]/td/div[@id="{key.value}"]')[0]) # 课程

    all_courses = {}

    for k, v in data.items():
        for i in range(len(v)):
            courses = process_course(v[i])
            for course in courses:
                key = f'{course["courseName"]}-{course["teacher"]}'
                if key not in all_courses:
                    all_courses[key] = {
                        'courseName': course['courseName'],
                        'teacher': course['teacher'],
                        'schedule': []
                    }
                schedule = {
                    'weeks': course['weeks'],
                    'dayOfWeek': days[row[i]],
                    'period': periods[col[i]],
                    'adjust_course': course.get('adjust_course', False),
                    'adjust_course_type': course.get('adjust_course_type', ''),
                    'location': course['location'],
                }
                all_courses[key]['schedule'].append(schedule)

    remarks = root.xpath(f'//tr[{len(col) + 1}]/td')[0].text_content().strip()

    data = {
        "semester": semester,
        "remarks": remarks,
        "time": period_times,
        "courses": []
    }

    for v in all_courses.values():
        data["courses"].append(v)

    return data
