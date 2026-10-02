function getCookie(name) {
	const value = `; ${document.cookie}`;
	const parts = value.split(`; ${name}=`);
	if (parts.length === 2) return parts.pop().split(';').shift();
	return '';
}

function initScanForm() {
	const form = document.querySelector('[data-scan-form]');
	if (!form) return;

	const activeField = form.querySelector('[data-scan-active]');
	const tabs = form.querySelectorAll('[data-scan-tab]');
	const urlInput = form.querySelector('[data-scan-url-input]');
	const fileInput = form.querySelector('[data-scan-file-input]');
	const fileLabel = form.querySelector('[data-scan-file-name]');
	const submitButton = form.querySelector('[data-scan-submit]');
	const urlPanel = form.querySelector('[data-scan-url-panel]');
	const qrPanel = form.querySelector('[data-scan-qr-panel]');

	const setActive = (tab) => {
		activeField.value = tab;
		if (urlPanel) urlPanel.classList.toggle('hidden', tab !== 'url');
		if (qrPanel) qrPanel.classList.toggle('hidden', tab !== 'qr');
		tabs.forEach((button) => {
			const isActive = button.dataset.scanTab === tab;
			button.className = isActive
				? 'flex-1 py-3 flex items-center justify-center gap-2 rounded-lg text-sm font-medium text-blue-600 bg-white shadow-sm ring-1 ring-black/5'
				: 'flex-1 py-3 flex items-center justify-center gap-2 rounded-lg text-sm font-medium text-slate-500 hover:text-slate-700 hover:bg-slate-200/50';
		});
	};

	tabs.forEach((button) => {
		button.addEventListener('click', () => {
			setActive(button.dataset.scanTab);
			if (fileInput) fileInput.value = '';
			if (fileLabel) fileLabel.textContent = 'คลิกเพื่ออัปโหลดรูปภาพ QR Code';
		});
	});

	if (fileInput && fileLabel) {
		fileInput.addEventListener('change', () => {
			fileLabel.textContent = fileInput.files.length ? fileInput.files[0].name : 'คลิกเพื่ออัปโหลดรูปภาพ QR Code';
		});
	}

	form.addEventListener('submit', async (event) => {
		event.preventDefault();

		const activeTab = activeField.value;
		const targetUrl = activeTab === 'qr'
			? 'http://mock-qr-extracted-link.com/scanned-from-image'
			: urlInput.value.trim();

		if (activeTab === 'url' && !targetUrl) {
			alert('กรุณากรอกลิงก์ URL ที่ต้องการตรวจสอบก่อนครับ');
			return;
		}

		if (activeTab === 'qr' && (!fileInput || !fileInput.files.length)) {
			alert('กรุณาเลือกอัปโหลดไฟล์ภาพ QR Code ก่อนครับ');
			return;
		}

		submitButton.disabled = true;
		const originalHtml = submitButton.innerHTML;
		submitButton.innerHTML = '<span class="flex items-center gap-1.5"><span class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></span>ตรวจอยู่...</span>';

		try {
			const response = await fetch('/api/v1/scan/', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-CSRFToken': getCookie('csrftoken'),
				},
				body: JSON.stringify({ url: targetUrl }),
			});

			if (!response.ok) {
				throw new Error('scan failed');
			}

			const result = await response.json();
			sessionStorage.setItem('phishwise:lastScan', JSON.stringify(result));
			window.location.href = '/result/';
		} catch (error) {
			console.error(error);
			alert('⚠️ ไม่สามารถเชื่อมต่อกับระบบประมวลผลหลังบ้านได้');
		} finally {
			submitButton.disabled = false;
			submitButton.innerHTML = originalHtml;
		}
	});

	setActive(activeField.value || 'url');
}

function initResultPage() {
	const mount = document.querySelector('[data-result-page]');
	if (!mount || mount.dataset.resultRendered === '1') return;

	const raw = sessionStorage.getItem('phishwise:lastScan');
	if (!raw) return;

	const result = JSON.parse(raw);
	const safetyScore = Number(result.score || 0);
	const riskScore = Number(result.ai_risk_score ?? (100 - safetyScore));
	const status = result.status || (safetyScore >= 75 ? 'safe' : safetyScore >= 45 ? 'warning' : 'danger');
	const theme = status === 'safe'
		? { color: '#16a34a', badge: 'bg-green-100 text-green-700 border-green-200', bg: 'bg-green-50', label: 'ปลอดภัย' }
		: status === 'warning'
			? { color: '#f59e0b', badge: 'bg-orange-100 text-orange-700 border-orange-200', bg: 'bg-orange-50', label: 'มีความเสี่ยง' }
			: { color: '#dc2626', badge: 'bg-red-100 text-red-700 border-red-200', bg: 'bg-red-50', label: 'อันตราย' };

	const setText = (selector, value) => {
		const node = document.querySelector(selector);
		if (node) node.textContent = value;
	};

	setText('[data-result-status]', theme.label);
	setText('[data-result-url]', result.url || 'ไม่ระบุ URL');
	setText('[data-safety-score]', `${safetyScore}%`);
	setText('[data-risk-score]', `${riskScore}/100`);
	setText('[data-ssl-title]', result.ssl_title || 'Not Secure');
	setText('[data-ssl-sub]', result.ssl_sub || '');
	setText('[data-domain-age]', result.domain_age || 'ไม่พบข้อมูล');
	setText('[data-domain-sub]', result.domain_sub || '');
	setText('[data-location]', result.location || 'Unknown');
	setText('[data-redirection]', result.has_redirection ? 'ตรวจพบการส่งต่อ' : 'ไม่มีการส่งต่อ');
	setText('[data-blacklist-status]', result.is_blacklisted ? 'พบความเสี่ยง' : 'ปลอดภัย');
	setText('[data-google-safe]', result.google_safe ? 'ปลอดภัย' : 'อันตราย');

	const gauge = document.querySelector('[data-gauge]');
	if (gauge) {
		gauge.style.background = `conic-gradient(${theme.color} 0% ${safetyScore}%, transparent ${safetyScore}% 100%)`;
	}

	const riskBar = document.querySelector('[data-risk-bar]');
	if (riskBar) {
		riskBar.style.width = `${riskScore}%`;
		riskBar.style.backgroundColor = theme.color;
	}

	const badge = document.querySelector('[data-result-badge]');
	if (badge) {
		badge.className = `px-3 py-1 text-xs font-bold rounded-full border ${theme.badge}`;
	}
}

document.addEventListener('DOMContentLoaded', () => {
	initScanForm();
	initResultPage();
});