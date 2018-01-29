def parse_http ( data ):
	fields = data.split("\r\n")
	#fields = fields[1:] #ignore the GET / HTTP/1.1
	output = {}
	'''
	for field in fields:
		print ( )
		#key,value = field.split(':')#split each line by http field name and value
		#output[key] = value
	'''
	#return output
	return fields

