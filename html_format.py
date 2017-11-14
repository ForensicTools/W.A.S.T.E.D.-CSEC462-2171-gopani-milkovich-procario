import os
import json
import time

data = json.load(open('/home/sansforensics/Desktop/project/html_json.json'))

file2 = open("/home/sansforensics/Desktop/project/html_txt.txt", "w")

for key,value in data.items():

	svgpath = value['svgPath']
	zoomlevel = value['zoomLevel']
	scale = value['scale']
	title = value['title']
	latitude = value['Latitude']
	longitude = value['Longitude']
	color = value['color']
	selectedcolor = value['selectedColor']

	string = "{\n      \"svgPath\": %s,\n      \"zoomLevel\": %s,\n      \"scale\": %s,\n      \"title\": \"%s\",\n      \"latitude\": %s,\n      \"longitude\": %s,\n      \"color\": \"%s\",\n      \"selectedColor\": \"%s\"\n    }, " % (svgpath,zoomlevel,scale,title,latitude,longitude,color,selectedcolor)

	file2.write(string)

file2.close()

