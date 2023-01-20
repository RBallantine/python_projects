'''
    Traverses a given timespan (in days)
    and writes all paths to a text file
'''

import os
import datetime


directory = os.path.join('/Users', 'ronan', 'Documents')
year = int(input('Enter year: '))
month = int(input('Enter month: '))
day = int(input('Enter day: '))
offset = int(input('Enter offfset: '))

date = datetime.date(year, month, day)
start = date + datetime.timedelta(days=offset)

with open('file_paths.txt', 'w') as f:

    i = 0
    delta = datetime.timedelta(days=1)
    while i <= (abs((date - start).days)):
        month = str(date.month).zfill(2)
        day = str(date.day).zfill(2)
        path = os.path.join(directory, str(date.year), month, day)
        
        files = os.listdir(path)
        for file in files:
            full_path = os.path.join(path, file)
            f.writelines(f'{full_path}\n')

        if abs((date - start).days) == 0:
            break
        else: pass

        if date < start:
            date += delta
        else:
            date -= delta
