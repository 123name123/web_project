from flask_restful import Resource, abort
from data import db_session, products
from flask import jsonify
from product_parser import parser


class ProductResource(Resource):
    def get(self, product_id):
        abort_if_product_not_found(product_id)
        session = db_session.create_session()
        product = session.query(products.Products).get(product_id)
        return jsonify({
            'product': product.to_dict(only=('id', 'title', 'price', 'existence', 'about',
                                             'still_have'))
        })

    def delete(self, product_id):
        abort_if_product_not_found(product_id)
        session = db_session.create_session()
        product = session.query(products.Products).get(product_id)
        session.delete(product)
        session.commit()
        return jsonify({'success': 'OK'})


def abort_if_product_not_found(product_id):
    sessoin = db_session.create_session()
    product = sessoin.query(products.Products).get(product_id)
    if not product:
        abort(404, message=f'Product {product_id} not found')


class ProductListResource(Resource):
    def get(self):
        session = db_session.create_session()
        product = session.query(products.Products).all()
        return jsonify({'products': [item.to_dict(only=('id', 'title', 'price', 'existence',
                                                        'about', 'still_have'))
                                     for item in product]})

    def post(self):
        args = parser.parse_args()
        session = db_session.create_session()
        product = products.Products(
            title=args['title'],
            price=args['price'],
            about=args['about'],
            existence=args['existence'],
            still_have=args['still_have']
        )
        session.add(product)
        session.commit()
        return jsonify({'success': 'OK'})
