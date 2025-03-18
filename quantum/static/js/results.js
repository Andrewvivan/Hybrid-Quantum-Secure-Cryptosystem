function initBackground() {
    if (typeof THREE === 'undefined') {
        console.error('Three.js is not loaded. Please include Three.js library.');
        return;
    }

    if (!document.getElementById('bg')) {
        const canvas = document.createElement('canvas');
        canvas.id = 'bg';
        document.body.appendChild(canvas);
    }

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ 
        canvas: document.getElementById('bg'),
        alpha: true,
        antialias: true
    });
    renderer.setPixelRatio(window.devicePixelRatio);
    renderer.setSize(window.innerWidth, window.innerHeight);

    camera.position.setZ(30);

    const particleGeometry = new THREE.BufferGeometry();
    const particleCount = 1000;

    const posArray = new Float32Array(particleCount * 3);
    const scaleArray = new Float32Array(particleCount);

    for(let i = 0; i < particleCount * 3; i += 3) {
        const radius = 50 + Math.random() * 70;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.random() * Math.PI;
        
        posArray[i] = radius * Math.sin(phi) * Math.cos(theta);
        posArray[i+1] = radius * Math.sin(phi) * Math.sin(theta);
        posArray[i+2] = radius * Math.cos(phi);

        scaleArray[i/3] = Math.random() * 0.5 + 0.1;
    }

    particleGeometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
    particleGeometry.setAttribute('scale', new THREE.BufferAttribute(scaleArray, 1));

    const particleMaterial = new THREE.ShaderMaterial({
        uniforms: {
            time: { value: 0.0 },
            color: { value: new THREE.Color(0x00d2ff) }
        },
        vertexShader: `
            attribute float scale;
            uniform float time;
            
            void main() {
                vec3 pos = position;
                
                // Add some subtle movement
                pos.x += sin(time * 0.2 + position.z * 0.1) * 2.0;
                pos.y += cos(time * 0.1 + position.x * 0.1) * 2.0;
                pos.z += sin(time * 0.3 + position.y * 0.1) * 2.0;
                
                vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
                gl_PointSize = scale * (300.0 / -mvPosition.z);
                gl_Position = projectionMatrix * mvPosition;
            }
        `,
        fragmentShader: `
            uniform vec3 color;
            
            void main() {
                // Create circular particles with soft edges
                float distance = length(gl_PointCoord - vec2(0.5, 0.5));
                if (distance > 0.5) discard;
                
                float alpha = smoothstep(0.5, 0.4, distance);
                gl_FragColor = vec4(color, alpha * 0.7);
            }
        `,
        transparent: true,
        depthWrite: false,
        blending: THREE.AdditiveBlending
    });

    const particleSystem = new THREE.Points(particleGeometry, particleMaterial);
    scene.add(particleSystem);

    const orbsCount = 20;
    const orbs = new THREE.Group();

    const orbGeometry = new THREE.SphereGeometry(0.5, 8, 8);
    const orbMaterial = new THREE.MeshBasicMaterial({
        color: 0x4299ff,
        transparent: true,
        opacity: 0.6
    });

    for (let i = 0; i < orbsCount; i++) {
        const orb = new THREE.Mesh(orbGeometry, orbMaterial);

        const radius = 30 + Math.random() * 50;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.random() * Math.PI;
        
        orb.position.x = radius * Math.sin(phi) * Math.cos(theta);
        orb.position.y = radius * Math.sin(phi) * Math.sin(theta);
        orb.position.z = radius * Math.cos(phi);

        const scale = Math.random() * 2.5 + 0.8;
        orb.scale.set(scale, scale, scale);

        orb.userData.initialPos = orb.position.clone();
        orb.userData.moveFactor = Math.random() * 2 + 1;
        
        orbs.add(orb);
    }

    scene.add(orbs);

    const lineMaterial = new THREE.LineBasicMaterial({
        color: 0x00d2ff,
        transparent: true,
        opacity: 0.2
    });

    const lines = new THREE.Group();

    for (let i = 0; i < orbsCount; i++) {
        for (let j = i + 1; j < orbsCount; j++) {
            const distance = orbs.children[i].position.distanceTo(orbs.children[j].position);
            
            if (distance < 30) {
                const lineGeometry = new THREE.BufferGeometry().setFromPoints([
                    orbs.children[i].position,
                    orbs.children[j].position
                ]);
                
                const line = new THREE.Line(lineGeometry, lineMaterial);
                line.userData.startIdx = i;
                line.userData.endIdx = j;
                lines.add(line);
            }
        }
    }

    scene.add(lines);

    const clock = new THREE.Clock();

    function animate() {
        requestAnimationFrame(animate);
        
        const elapsedTime = clock.getElapsedTime();

        particleMaterial.uniforms.time.value = elapsedTime;
        particleSystem.rotation.x = elapsedTime * 0.03;
        particleSystem.rotation.y = elapsedTime * 0.02;

        orbs.children.forEach((orb) => {
            const initialPos = orb.userData.initialPos;
            const factor = orb.userData.moveFactor;

            orb.position.x = initialPos.x + Math.sin(elapsedTime * 0.2 * factor) * 3;
            orb.position.y = initialPos.y + Math.cos(elapsedTime * 0.3 * factor) * 3;
            orb.position.z = initialPos.z + Math.sin(elapsedTime * 0.4 * factor) * 3;
        });

        lines.children.forEach(line => {
            const startOrb = orbs.children[line.userData.startIdx];
            const endOrb = orbs.children[line.userData.endIdx];
            
            const positions = line.geometry.attributes.position.array;
            
            positions[0] = startOrb.position.x;
            positions[1] = startOrb.position.y;
            positions[2] = startOrb.position.z;
            
            positions[3] = endOrb.position.x;
            positions[4] = endOrb.position.y;
            positions[5] = endOrb.position.z;
            
            line.geometry.attributes.position.needsUpdate = true;
        });
        
        renderer.render(scene, camera);
    }

    animate();

    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });

    document.addEventListener('mousemove', (event) => {
        const mouseX = (event.clientX / window.innerWidth) * 2 - 1;
        const mouseY = -(event.clientY / window.innerHeight) * 2 + 1;
        
        camera.position.x = mouseX * 5;
        camera.position.y = mouseY * 5;
        camera.lookAt(scene.position);
    });
}

function createQuantumParticles() {
    for (let i = 0; i < 25; i++) {
        const particle = document.createElement('div');
        particle.classList.add('quantum-particle');

        const size = Math.random() * 15 + 5;
        particle.style.width = `${size}px`;
        particle.style.height = `${size}px`;

        const posX = Math.random() * window.innerWidth;
        const posY = Math.random() * window.innerHeight;
        particle.style.left = `${posX}px`;
        particle.style.top = `${posY}px`;

        particle.style.opacity = Math.random() * 0.5 + 0.1;

        const animDuration = Math.random() * 10 + 10;
        particle.style.animation = `float ${animDuration}s infinite ease-in-out`;
        particle.style.animationDelay = `${Math.random() * 5}s`;
        
        document.body.appendChild(particle);
    }
}

function setupAdjustableRectangles() {
    const rectItems = document.querySelectorAll('.rect-item');
    rectItems.forEach(rect => {
        if (window.innerWidth < 768) {
            rect.style.width = "100%";
            rect.style.height = "auto";
            rect.style.margin = "10px 0";
        } else {
            const width = rect.getAttribute('data-width') || "250px";
            const height = rect.getAttribute('data-height') || "140px";
            rect.style.width = width;
            rect.style.height = height;
            rect.style.margin = "0 15px 30px";
        }
    });
}

function setupResultText() {
    const resultMessage = document.querySelector('.result-message');
    if (resultMessage) {
        resultMessage.style.animation = 'pulse 3s infinite ease-in-out';
    }
}

function adjustButtonSizes() {
    const homeButton = document.querySelector('.home-button');
    
    if (window.innerWidth > 768) {
        if (homeButton) {
            homeButton.style.width = "130px";
            homeButton.style.height = "80px";
        }
    } else {
        if (homeButton) {
            homeButton.style.width = "120px";
            homeButton.style.height = "40px";
        }
    }
}

document.addEventListener('DOMContentLoaded', function() {
    if (typeof THREE !== 'undefined') {
        initBackground();
    } else {
        console.warn('Three.js not found. Skipping 3D background initialization.');
    }

    createQuantumParticles();
    setupAdjustableRectangles();
    setupResultText();
    adjustButtonSizes();

    window.addEventListener('resize', function() {
        setupAdjustableRectangles();
        adjustButtonSizes();
    });
});