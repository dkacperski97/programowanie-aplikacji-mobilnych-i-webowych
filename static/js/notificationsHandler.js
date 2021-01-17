fetch(`/ws-url`).then((res) => {
	if (res.status === 200) {
		res.json().then((value) => {
			const token = document.cookie
				.split('; ')
				.find((c) => c.startsWith('Authorization'))
				.split('=')[1]
				.replace('Bearer ', '');

			let ws = new WebSocket(value.url + '/notifications/ws', token);
			ws.onopen = (event) => {
				console.log('WebSocket onOpen');
			};
			ws.onmessage = (event) => {
				if (document.getElementsByTagName('aside').length === 0) {
					initAside();
				}
				const notifications = document.getElementById('notifications');
				const notification = document.createElement('li');
				const link = document.createElement('a');
				link.setAttribute('href', '/sender/dashboard');
				link.textContent = event.data;
				notification.appendChild(link);
				notifications.appendChild(notification);
				setTimeout(() => {
					notification.remove();
					if (document.querySelectorAll('#notifications li').length === 0) {
						removeAside();
					}
				}, 10000);
			};
			ws.onerror = function (e) {
				console.log(e);
			};

			const initAside = () => {
				const aside = document.createElement('aside');
				const list = document.createElement('ul');
				list.setAttribute('id', 'notifications');
				aside.appendChild(list);
				const bodyArray = document.getElementsByTagName('body');
				if (bodyArray.length > 0) {
					bodyArray[0].appendChild(aside);
				}
			};
			const removeAside = () => {
				const asideArray = document.getElementsByTagName('aside');
				if (asideArray.length > 0) {
					asideArray[0].remove();
				}
			};
		});
	}
});
