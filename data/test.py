from requests import get, post

print(post('http://localhost:5000/api/jobs').json())
print(post('http://localhost:5000/api/jobs',
           json={'job': 'error'}).json())
print(post('http://localhost:5000/api/jobs',
           json={'id': 2,
                 'job': 'Work',
                 'team_leader': 1,
                 'work_size': 1,
                 'collaborators': '3, 4',
                 'is_finished': True}).json())

print(post('http://localhost:5000/api/jobs',
           json={'job': 'Work',
                 'team_leader': 1,
                 'work_size': 1,
                 'collaborators': '3, 4',
                 'is_finished': True}).json())

print(get('http://localhost:5000/api/jobs').json())
