from requests import post

print(post('http://localhost:5000/api/v2/products',  # Корректный запрос
           json={'title': 'Маски 2',
                 'about': 'Прекрасные маски',
                 'price': 500,
                 'existence': True,
                 'still_have': 10}).json())
