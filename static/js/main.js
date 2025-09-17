(function(){
	function qs(s){return document.querySelector(s)}
	function qsa(s){return document.querySelectorAll(s)}
	function show(el){el.classList.remove('d-none')}
	function hide(el){el.classList.add('d-none')}
	function toast(msg, type){
		var cont = qs('#toast-container'); if(!cont) return;
		var t = document.createElement('div');
		t.className = 'toast align-items-center text-bg-' + (type||'primary') + ' show mb-2';
		t.setAttribute('role','alert');
		t.innerHTML = '<div class="d-flex"><div class="toast-body">' + msg + '</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div>';
		cont.appendChild(t);
		setTimeout(()=>{ t.remove(); }, 4000);
	}

	// Tab switching
	var tabBtns = qsa('.tab-btn');
	var tabContents = qsa('.tab-content');
	tabBtns.forEach(btn => {
		btn.addEventListener('click', function(){
			var targetTab = this.dataset.tab;
			tabBtns.forEach(b => b.classList.remove('active'));
			tabContents.forEach(c => c.classList.remove('active'));
			this.classList.add('active');
			qs('#' + targetTab + '-tab').classList.add('active');
		});
	});

	// Theme
	var root = document.documentElement;
	function applyTheme(){
		var saved = localStorage.getItem('theme')||'dark';
		root.setAttribute('data-theme', saved==='light'?'light':'dark');
		var sw = qs('#themeSwitch'); if(sw){ sw.checked = (saved!=='light'); }
	}
	applyTheme();
	var sw = qs('#themeSwitch'); if(sw){
		sw.addEventListener('change', function(){
			var theme = this.checked ? 'dark' : 'light';
			localStorage.setItem('theme', theme); applyTheme();
		});
	}

	function setupDropZone(id){
		var dz = qs(id); if(!dz) return;
		dz.addEventListener('dragover', e=>{ e.preventDefault(); dz.classList.add('dragover'); });
		dz.addEventListener('dragleave', ()=> dz.classList.remove('dragover'));
		dz.addEventListener('drop', ()=> dz.classList.remove('dragover'));
	}
	setupDropZone('#cover-drop');
	setupDropZone('#stego-drop');

	// File preview & capacity
	function bytesToHuman(n){ if(n<1024) return n+' B'; var k=n/1024; if(k<1024) return k.toFixed(1)+' KB'; return (k/1024).toFixed(2)+' MB'; }
	
	// Cover file preview (for embed section)
	var coverInput = qs('#cover');
	if(coverInput){
		coverInput.addEventListener('change', function(){
			var file = this.files && this.files[0];
			var prev = qs('#cover-preview'); if(prev) prev.innerHTML='';
			var hint = qs('#capacity-hint'); if(hint) hint.textContent='';
			var actions = qs('#cover-actions');
			
			if(!file) {
				if(actions) actions.classList.add('d-none');
				return;
			}
			
			// Show filename and size for all file types
			if(prev){ 
				var fileIcon = file.type.startsWith('image/') ? '🖼️' : 
							  file.type.startsWith('audio/') ? '🎵' : 
							  file.type.startsWith('video/') ? '🎬' : '📄';
				prev.innerHTML = '<div class="file-preview"><span class="file-icon">' + fileIcon + '</span><span class="file-name">' + file.name + '</span><span class="file-size">(' + bytesToHuman(file.size) + ')</span></div>';
			}
			
			// Show remove button
			if(actions) actions.classList.remove('d-none');
			
			// Calculate capacity for images only (without showing the image)
			if(file.type.startsWith('image/')){
				var img = new Image();
				img.onload = function(){
					var capBits = img.width * img.height * 3; // 1 LSB each channel
					var capBytes = Math.floor(capBits/8) - 8; // minus header
					if(hint){ hint.textContent = 'Estimated capacity: ' + bytesToHuman(Math.max(capBytes,0)) + ' (image LSB)'; }
				};
				img.src = URL.createObjectURL(file);
			}
		});
	}
	
	// Remove cover file
	var removeCoverBtn = qs('#remove-cover');
	if(removeCoverBtn){
		removeCoverBtn.addEventListener('click', function(){
			var coverInput = qs('#cover');
			var prev = qs('#cover-preview');
			var hint = qs('#capacity-hint');
			var actions = qs('#cover-actions');
			
			if(coverInput) coverInput.value = '';
			if(prev) prev.innerHTML = '';
			if(hint) hint.textContent = '';
			if(actions) actions.classList.add('d-none');
			
			toast('Cover file removed', 'info');
		});
	}
	
	// Secret file preview (for embed section)
	var secretInput = qs('#secret');
	if(secretInput){
		secretInput.addEventListener('change', function(){
			var file = this.files && this.files[0];
			var actions = qs('#secret-actions');
			
			if(!file) {
				if(actions) actions.classList.add('d-none');
				return;
			}
			
			// Show remove button
			if(actions) actions.classList.remove('d-none');
		});
	}
	
	// Remove secret file
	var removeSecretBtn = qs('#remove-secret');
	if(removeSecretBtn){
		removeSecretBtn.addEventListener('click', function(){
			var secretInput = qs('#secret');
			var actions = qs('#secret-actions');
			
			if(secretInput) secretInput.value = '';
			if(actions) actions.classList.add('d-none');
			
			toast('Secret file removed', 'info');
		});
	}
	
	// Stego file preview (for extract section)
	var stegoInput = qs('#stego');
	if(stegoInput){
		stegoInput.addEventListener('change', function(){
			var file = this.files && this.files[0];
			var prev = qs('#stego-preview'); if(prev) prev.innerHTML='';
			var actions = qs('#stego-actions');
			
			if(!file) {
				if(actions) actions.classList.add('d-none');
				return;
			}
			
			// Show filename and size for all file types (same as embed section)
			if(prev){ 
				var fileIcon = file.type.startsWith('image/') ? '🖼️' : 
							  file.type.startsWith('audio/') ? '🎵' : 
							  file.type.startsWith('video/') ? '🎬' : '📄';
				prev.innerHTML = '<div class="file-preview"><span class="file-icon">' + fileIcon + '</span><span class="file-name">' + file.name + '</span><span class="file-size">(' + bytesToHuman(file.size) + ')</span></div>';
			}
			
			// Show remove button
			if(actions) actions.classList.remove('d-none');
		});
	}
	
	// Remove stego file
	var removeStegoBtn = qs('#remove-stego');
	if(removeStegoBtn){
		removeStegoBtn.addEventListener('click', function(){
			var stegoInput = qs('#stego');
			var prev = qs('#stego-preview');
			var actions = qs('#stego-actions');
			
			if(stegoInput) stegoInput.value = '';
			if(prev) prev.innerHTML = '';
			if(actions) actions.classList.add('d-none');
			
			toast('Stego file removed', 'info');
		});
	}

	function setAlgoVisibility(){
		var algo = qs('#algo'); if(!algo) return;
		var aes = qs('#aes-password'); var rsa = qs('#rsa-public');
		if(algo.value === 'rsa'){ hide(aes); rsa.classList.remove('d-none'); }
		else { rsa.classList.add('d-none'); show(aes); }
	}
	var algoSel = qs('#algo'); if(algoSel){ algoSel.addEventListener('change', setAlgoVisibility); setAlgoVisibility(); }

	// Embed
	var embedForm = qs('#embed-form');
	if(embedForm){
		var embedBtn = qs('#embed-btn'); var embedSpin = qs('#embed-btn-spin');
		embedForm.addEventListener('submit', async function(e){
			e.preventDefault();
			var fd = new FormData(embedForm);
			hide(qs('#error')); hide(qs('#result'));
			try{
				embedBtn.disabled = true; show(embedSpin);
				var res = await fetch('/api/embed', { method:'POST', body: fd });
				var data = await res.json();
				if(!res.ok){ throw new Error(data.error || 'Embedding failed'); }
				qs('#download-link').href = data.download_url;
				var text = encodeURIComponent('Here is your stego-file generated by Stegano: ' + data.download_url);
				qs('#share-email').href = 'mailto:?subject=' + encodeURIComponent('Stegano stego-file') + '&body=' + text;
				qs('#share-wa').href = 'https://wa.me/?text=' + text;
				qs('#share-tg').href = 'https://t.me/share/url?url=' + encodeURIComponent(data.download_url) + '&text=' + text;
				show(qs('#result')); toast('Stego file created successfully','success');
			}catch(err){ var el = qs('#error'); el.textContent = err.message; show(el); toast(err.message,'danger'); }
			finally{ embedBtn.disabled = false; hide(embedSpin); }
		});
	}

	// Extract
	var extractForm = qs('#extract-form');
	if(extractForm){
		var extractBtn = qs('#extract-btn'); var extractSpin = qs('#extract-btn-spin');
		var extractPreview = qs('#extract-preview'); var extractContent = qs('#extract-content');
		var downloadBtn = qs('#download-extracted');
		var extractedBlob = null; var extractedFilename = '';

		extractForm.addEventListener('submit', async function(e){
			e.preventDefault();
			var fd = new FormData(extractForm);
			hide(qs('#x-error')); hide(extractPreview);
			try{
				extractBtn.disabled = true; show(extractSpin);
				var res = await fetch('/api/extract', { method:'POST', body: fd });
				if(!res.ok){
					var data = await res.json().catch(()=>({error:'Extraction failed'}));
					throw new Error(data.error || 'Extraction failed');
				}
				extractedBlob = await res.blob();
				var cd = res.headers.get('Content-Disposition')||'';
				var m = cd.match(/filename="?([^";]+)"?/); extractedFilename = (m && m[1]) || 'secret.bin';
				
				// Show preview
				extractContent.innerHTML = '';
				if(extractedFilename.match(/\.(txt|json|md|log)$/i)){
					var text = await extractedBlob.text();
					extractContent.innerHTML = '<div class="preview-text">' + text.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>';
				}else{
					var size = (extractedBlob.size / 1024).toFixed(1) + ' KB';
					extractContent.innerHTML = '<div class="file-info"><div class="file-icon">📄</div><div><strong>' + extractedFilename + '</strong><br><small>' + size + '</small></div></div>';
				}
				show(extractPreview);
				toast('Secret extracted successfully','success');
			}catch(err){ var el = qs('#x-error'); el.textContent = err.message; show(el); toast(err.message,'danger'); }
			finally{ extractBtn.disabled = false; hide(extractSpin); }
		});

		// Download button
		if(downloadBtn){
			downloadBtn.addEventListener('click', function(){
				if(extractedBlob){
					var a = document.createElement('a'); a.href = URL.createObjectURL(extractedBlob); a.download = extractedFilename; a.click();
				}
			});
		}
	}
	
	// Login/Profile functionality
	function checkLoginStatus() {
		var isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
		var profileSection = qs('#profileSection');
		var loginBtn = qs('#loginBtn');
		var demoLoginBtn = qs('#demoLoginBtn');
		
		if (isLoggedIn) {
			hide(loginBtn);
			hide(demoLoginBtn);
			show(profileSection);
			updateProfileInfo();
		} else {
			show(loginBtn);
			show(demoLoginBtn);
			hide(profileSection);
		}
	}
	
	function updateProfileInfo() {
		var userName = localStorage.getItem('userName') || 'User';
		var userRole = localStorage.getItem('userRole') || 'Administrator';
		var userEmail = localStorage.getItem('userEmail') || 'user@stegano.com';
		var profileImage = localStorage.getItem('profileImage');
		var initials = userName.split(' ').map(n => n[0]).join('').toUpperCase();
		
		// Update all profile elements
		qs('#userName').textContent = userName;
		qs('#userNameLarge').textContent = userName;
		qs('#userRole').textContent = userRole;
		qs('#userEmail').textContent = userEmail;
		qs('#userInitials').textContent = initials;
		qs('#userInitialsLarge').textContent = initials;
		
		// Handle profile image
		if (profileImage) {
			qs('#profileImage').src = profileImage;
			qs('#profileImage').style.display = 'block';
			qs('#avatarCircle').style.display = 'none';
			
			qs('#profileImageLarge').src = profileImage;
			qs('#profileImageLarge').style.display = 'block';
			qs('#avatarCircleLarge').style.display = 'none';
		} else {
			qs('#profileImage').style.display = 'none';
			qs('#avatarCircle').style.display = 'flex';
			
			qs('#profileImageLarge').style.display = 'none';
			qs('#avatarCircleLarge').style.display = 'flex';
		}
	}
	
	function logout() {
		// Close dropdown first
		qs('.profile-dropdown').classList.remove('active');
		document.body.classList.remove('dropdown-open');
		document.removeEventListener('click', handleClickOutside);
		
		localStorage.removeItem('isLoggedIn');
		localStorage.removeItem('userName');
		localStorage.removeItem('userRole');
		checkLoginStatus();
		toast('Logged out successfully', 'success');
	}
	
	// Simulate login (for demo purposes)
	function simulateLogin() {
		localStorage.setItem('isLoggedIn', 'true');
		localStorage.setItem('userName', 'John Doe');
		localStorage.setItem('userRole', 'Security Analyst');
		checkLoginStatus();
		toast('Welcome back, John!', 'success');
	}
	
	// Profile dropdown functionality
	function toggleProfileDropdown() {
		var dropdown = qs('.profile-dropdown');
		var isActive = dropdown.classList.contains('active');
		
		// Close all other dropdowns first
		qsa('.profile-dropdown').forEach(d => d.classList.remove('active'));
		
		if (!isActive) {
			dropdown.classList.add('active');
			document.body.classList.add('dropdown-open');
			
			// Add click outside listener
			setTimeout(() => {
				document.addEventListener('click', handleClickOutside);
			}, 100);
		} else {
			document.body.classList.remove('dropdown-open');
			document.removeEventListener('click', handleClickOutside);
		}
	}
	
	function handleClickOutside(event) {
		var dropdown = qs('.profile-dropdown');
		if (dropdown && !dropdown.contains(event.target)) {
			dropdown.classList.remove('active');
			document.body.classList.remove('dropdown-open');
			document.removeEventListener('click', handleClickOutside);
		}
	}
	
	function changeProfilePicture() {
		var input = document.createElement('input');
		input.type = 'file';
		input.accept = 'image/*';
		input.onchange = function(e) {
			var file = e.target.files[0];
			if (file) {
				var reader = new FileReader();
				reader.onload = function(e) {
					localStorage.setItem('profileImage', e.target.result);
					updateProfileInfo();
					toast('Profile picture updated successfully', 'success');
				};
				reader.readAsDataURL(file);
			}
		};
		input.click();
	}
	
	function openProfileSettings() {
		// Close dropdown first
		qs('.profile-dropdown').classList.remove('active');
		document.body.classList.remove('dropdown-open');
		document.removeEventListener('click', handleClickOutside);
		
		// Create settings modal
		var modal = document.createElement('div');
		modal.className = 'modal fade';
		modal.innerHTML = `
			<div class="modal-dialog">
				<div class="modal-content">
					<div class="modal-header">
						<h5 class="modal-title">Profile Settings</h5>
						<button type="button" class="btn-close" data-bs-dismiss="modal"></button>
					</div>
					<div class="modal-body">
						<div class="mb-3">
							<label class="form-label">Full Name</label>
							<input type="text" class="form-control" id="settingsName" value="${localStorage.getItem('userName') || ''}">
						</div>
						<div class="mb-3">
							<label class="form-label">Email</label>
							<input type="email" class="form-control" id="settingsEmail" value="${localStorage.getItem('userEmail') || ''}">
						</div>
						<div class="mb-3">
							<label class="form-label">Role</label>
							<select class="form-select" id="settingsRole">
								<option value="Security Analyst" ${localStorage.getItem('userRole') === 'Security Analyst' ? 'selected' : ''}>Security Analyst</option>
								<option value="Administrator" ${localStorage.getItem('userRole') === 'Administrator' ? 'selected' : ''}>Administrator</option>
								<option value="Developer" ${localStorage.getItem('userRole') === 'Developer' ? 'selected' : ''}>Developer</option>
								<option value="User" ${localStorage.getItem('userRole') === 'User' ? 'selected' : ''}>User</option>
							</select>
						</div>
					</div>
					<div class="modal-footer">
						<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
						<button type="button" class="btn btn-primary" onclick="saveProfileSettings()">Save Changes</button>
					</div>
				</div>
			</div>
		`;
		
		document.body.appendChild(modal);
		var bsModal = new bootstrap.Modal(modal);
		bsModal.show();
		
		modal.addEventListener('hidden.bs.modal', function() {
			modal.remove();
		});
	}
	
	function saveProfileSettings() {
		var name = qs('#settingsName').value;
		var email = qs('#settingsEmail').value;
		var role = qs('#settingsRole').value;
		
		if (name && email) {
			localStorage.setItem('userName', name);
			localStorage.setItem('userEmail', email);
			localStorage.setItem('userRole', role);
			updateProfileInfo();
			toast('Profile updated successfully', 'success');
			
			// Close modal
			var modal = qs('.modal');
			if (modal) {
				var bsModal = bootstrap.Modal.getInstance(modal);
				bsModal.hide();
			}
		} else {
			toast('Please fill in all required fields', 'danger');
		}
	}
	
	function viewProfile() {
		// Close dropdown first
		qs('.profile-dropdown').classList.remove('active');
		document.body.classList.remove('dropdown-open');
		document.removeEventListener('click', handleClickOutside);
		
		// Create profile view modal
		var modal = document.createElement('div');
		modal.className = 'modal fade';
		modal.innerHTML = `
			<div class="modal-dialog modal-lg">
				<div class="modal-content">
					<div class="modal-header">
						<h5 class="modal-title">User Profile</h5>
						<button type="button" class="btn-close" data-bs-dismiss="modal"></button>
					</div>
					<div class="modal-body text-center">
						<div class="profile-view-avatar mb-3">
							<img id="profileViewImage" src="${localStorage.getItem('profileImage') || ''}" alt="Profile" class="profile-view-img" style="display: none;">
							<div class="avatar-circle-view" id="avatarCircleView">
								<span id="userInitialsView">${(localStorage.getItem('userName') || 'User').split(' ').map(n => n[0]).join('').toUpperCase()}</span>
							</div>
						</div>
						<h4>${localStorage.getItem('userName') || 'User'}</h4>
						<p class="text-muted">${localStorage.getItem('userEmail') || 'user@stegano.com'}</p>
						<span class="badge bg-primary">${localStorage.getItem('userRole') || 'Security Analyst'}</span>
						
						<div class="row mt-4">
							<div class="col-md-6">
								<div class="profile-stat">
									<h6>Files Processed</h6>
									<p class="h3 text-primary">${localStorage.getItem('filesProcessed') || '0'}</p>
								</div>
							</div>
							<div class="col-md-6">
								<div class="profile-stat">
									<h6>Account Created</h6>
									<p class="h3 text-success">${localStorage.getItem('accountCreated') ? 'Yes' : 'No'}</p>
								</div>
							</div>
						</div>
					</div>
					<div class="modal-footer">
						<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
						<button type="button" class="btn btn-primary" onclick="openProfileSettings()">Edit Profile</button>
					</div>
				</div>
			</div>
		`;
		
		// Handle profile image display
		var profileImage = localStorage.getItem('profileImage');
		if (profileImage) {
			qs('#profileViewImage').src = profileImage;
			qs('#profileViewImage').style.display = 'block';
			qs('#avatarCircleView').style.display = 'none';
		} else {
			qs('#profileViewImage').style.display = 'none';
			qs('#avatarCircleView').style.display = 'flex';
		}
		
		document.body.appendChild(modal);
		var bsModal = new bootstrap.Modal(modal);
		bsModal.show();
		
		modal.addEventListener('hidden.bs.modal', function() {
			modal.remove();
		});
	}
	
	// Close dropdown when clicking outside
	document.addEventListener('click', function(e) {
		var dropdown = qs('.profile-dropdown');
		if (dropdown && !dropdown.contains(e.target)) {
			dropdown.classList.remove('active');
		}
	});

	// Make functions global
	window.logout = logout;
	window.simulateLogin = simulateLogin;
	window.toggleProfileDropdown = toggleProfileDropdown;
	window.changeProfilePicture = changeProfilePicture;
	window.openProfileSettings = openProfileSettings;
	window.viewProfile = viewProfile;
	window.saveProfileSettings = saveProfileSettings;

	// Initialize login status
	checkLoginStatus();
})();
