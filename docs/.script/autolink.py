from os import path, walk
from glob import glob
exit()
__current__ = path.split(path.realpath(__file__))[0]
__parent__ = path.abspath(path.join(__current__, ".."))
start = b"<!--start-->"
end = b"<!--end-->"
exclude_dir = ["template", "attachment", "stylesheets"]
files_mtime = {}


def find_start(fd):
    fd.seek(0, 0)
    data = fd.read().encode('utf-8')
    index = data.find(start)
    if index != -1:
        fd.seek(index - 1, 0)
        fd.truncate()


for d in glob(__parent__ + "/*"):
    basename = path.basename(d)
    if basename in exclude_dir:
        continue
    for p, dirs, files in walk(d):
        basename = path.basename(p)
        target = basename + ".md"
        if target not in files:
            continue
        f = path.join(p, target)
        links = files + dirs
        with open(f, "a+", encoding="utf-8") as fd:
            find_start(fd)
            fd.write("\n" + start.decode())
            for link in links:
                fd.write("\n[](%s)" % (link))
            fd.write("\n" + end.decode())
