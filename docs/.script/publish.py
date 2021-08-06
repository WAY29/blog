import os
import sys
from os import path, walk
from glob import glob
from operator import itemgetter
from re import sub, DOTALL
import PyRSS2Gen
from datetime import datetime
import time

__current__ = path.split(path.realpath(__file__))[0]
__parent__ = path.abspath(path.join(__current__, ".."))
ignore_start = "#start"
ignore_end = "#end"
markdown_start = "<!--start-->"
markdown_end = "<!--end-->"

exclude_dir = ["template", "attachment", "stylesheets", "学习"]

files_mtime = {}


def w(fd, data, new_value, start, end):
    if data.find(start) != -1:
        fd.seek(0, 0)
        data = sub(fr"\n{start}(.*?){end}", new_value,
                   data, count=1, flags=DOTALL)
        fd.write(data)
    else:
        fd.write(data + new_value)


# update ignore
with open(path.join(__parent__, "../.gitignore"), "r", encoding="utf-8") as fd:
    ignore_data = fd.read()


with open(path.join(__parent__, "../.gitignore"), "w+", encoding="utf-8") as fd:
    value = "\n" + ignore_start
    for d in glob(__parent__ + "/*"):
        basename = path.basename(d)

        if basename in exclude_dir:
            continue

        for p, dirs, files in walk(d):
            target = path.basename(p) + ".md"
            if target in files:
                value += "\n" + target
            del files[files.index(target)]
            for fp in (f for f in files if f.endswith(".md")):
                files_mtime[path.join(path.relpath(p, __parent__), fp)] = (path.getmtime(
                    path.join(p, fp)), path.getctime(path.join(p, fp)))

    value += "\n" + ignore_end

    w(fd, ignore_data, value, ignore_start, ignore_end)


# update index.md
latest_articles = sorted(
    files_mtime.items(), key=itemgetter(1), reverse=True)[:10]
with open(path.join(__parent__, "index.md"), "r", encoding="utf-8") as fd:
    index_data = fd.read()


with open(path.join(__parent__, "index.md"), "w+", encoding="utf-8") as fd:
    value = "\n" + markdown_start + \
        "\n### Latest articles\n| articles | mtime |\n|  ----  | ----  |"
    for relfp, times in latest_articles:
        temp_relfp = relfp.replace("\\", "/")
        mtime = times[0]
        timeStruct = time.localtime(mtime)
        fname, _ = path.splitext(temp_relfp)
        update_time = "%s" % time.strftime('%Y/%m/%d', timeStruct)
        value += "\n|[%s](%s)|%s|" % (fname.replace("/", " - "),
                                      temp_relfp, update_time)
    value += "\n" + markdown_end
    w(fd, index_data, value, markdown_start, markdown_end)

# generate rss
items = []

with open(path.join(__parent__, "rss.xml"), "w+", encoding="utf-8") as rss_fd:
    for relfp, times in latest_articles:
        relfp = relfp.replace("\\", "/")
        ctime = times[1]
        temp_relfp = relfp.replace("\\", "/")
        fname, _ = path.splitext(temp_relfp)
        with open(path.join(__parent__, relfp), "r", encoding="utf-8") as fd:
            link = f"https://longlone.top/{relfp}/".replace(".md", "")
            data = fd.read()
            index = data.find("---", 4)
            if index == -1:
                index = 0
            desc = data[index + 3:index +
                        63].replace("\r", "").replace("\n", "")
            item = PyRSS2Gen.RSSItem(title=fname.replace(
                "/", " - "), link=link, description=desc, guid=PyRSS2Gen.Guid(link), pubDate=datetime.fromtimestamp(ctime))
            items.append(item)

    rss = PyRSS2Gen.RSS2(title="Longlone's Blog",  link="https://longlone.top/", description="Longlone's Blog about daily and security.",
                         language="zh", items=items, pubDate=datetime(2021, 6, 5, 0, 0, 0), lastBuildDate=datetime.now())
    prettyHTML = rss.to_xml(encoding="utf-8")
    rss_fd.write(prettyHTML)

if len(sys.argv) < 2:
    print("miss argv, exit")
    exit(1)

msg = sys.argv[1]
os.environ['http_proxy'] = "http://127.0.0.1:7890"
os.environ['https_proxy'] = "http://127.0.0.1:7890"
os.chdir("D:\\Coding\\blog")
os.system("git add --all")
os.system('git commit -m "%s"' % msg)
os.system("git push")
