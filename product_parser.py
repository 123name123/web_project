from flask_restful import reqparse


parser = reqparse.RequestParser()
parser.add_argument('title', required=True)
parser.add_argument('about', required=True)
parser.add_argument('existence', required=True, type=bool)
parser.add_argument('price', required=True)
parser.add_argument('still_have', required=True, type=int)
