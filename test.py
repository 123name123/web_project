from requests import post

print(post('http://localhost:5000/api/v2/products',  # Корректный запрос
           json={'title': 'Маски',
                 'about': 'Прекрасные маски',
                 'price': 500,
                 'existence': True}).json())