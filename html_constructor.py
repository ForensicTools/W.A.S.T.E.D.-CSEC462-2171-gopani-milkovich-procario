import os
import time

file = open("html_template.html", "r")
contents = file.readlines()
file.close()

imagesStart = "    \"images\": ["
imagesEnd = "]\n  },\n"

with open('/home/sansforensics/Desktop/project/html_txt.txt', 'r') as myfile:
	data=myfile.read().strip('\n')

putstuff = imagesStart + data + imagesEnd

contents.insert(98,putstuff)

file2 = open("/home/sansforensics/Desktop/thing/mapper.html", "w")
contents = "".join(contents)
file2.write(contents)
file2.close()

time.sleep(5)
os.system('/usr/bin/google-chrome /home/sansforensics/Desktop/thing/mapper.html')
