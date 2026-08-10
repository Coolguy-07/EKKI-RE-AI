/**
 * EKKI-RE-AI - Signature Computational Neural Core Engine
 * Powered by Three.js & GLSL Shaders
 * Interactive state-based transformations for REASON, CODE, SEE, ACT, ANALYZE, RESEARCH
 * Optimized for low VRAM & 60+ FPS on RTX 4050
 */

class HeroEngine {
    constructor() {
        this.canvas = document.getElementById('bg-canvas');
        if (!this.canvas) return;

        this.scene = null;
        this.camera = null;
        this.renderer = null;
        
        // 3D Visual Layers
        this.midgroundParticles = null;
        this.foregroundParticles = null;
        this.neuralLines = null;
        this.innerLattice = null;
        this.outerLattice = null;
        this.orbitalRing1 = null;
        this.orbitalRing2 = null;
        this.orbitalParticles = null;
        
        this.animFrameId = null;
        this.isRunning = false;
        this.clock = new THREE.Clock();
        
        // Interaction & Transformation States
        this.targetMouse = { x: 0, y: 0 };
        this.currentMouse = { x: 0, y: 0 };
        this.targetScroll = 0;
        this.currentScroll = 0;
        
        // Active Intelligence Mode State
        this.activeCapability = 0; // 0: Default, 1: Reason, 2: Code, 3: See, 4: Act, 5: Analyze, 6: Research
        this.targetExpansion = 1.0;
        this.currentExpansion = 1.0;
        this.targetOrbitalSpeed = 1.0;
        this.currentOrbitalSpeed = 1.0;
        this.targetLineOpacity = 0.08;
        this.currentLineOpacity = 0.08;
        
        this.init();
    }

    init() {
        if (typeof THREE === 'undefined') {
            console.warn('Three.js not loaded.');
            return;
        }

        // 1. Scene & Fog Setup
        this.scene = new THREE.Scene();
        this.scene.fog = new THREE.FogExp2(0x050609, 0.018);

        // 2. Camera Setup
        const aspect = window.innerWidth / window.innerHeight;
        this.camera = new THREE.PerspectiveCamera(36, aspect, 0.1, 1000);
        this.camera.position.set(0, 0, 22);

        // 3. Renderer Setup
        this.renderer = new THREE.WebGLRenderer({
            canvas: this.canvas,
            alpha: true,
            antialias: true,
            powerPreference: "high-performance"
        });
        this.renderer.setSize(window.innerWidth, window.innerHeight);
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));

        // 4. Core Container Group
        this.coreGroup = new THREE.Group();
        this.coreGroup.position.set(0, 0, -2);
        this.scene.add(this.coreGroup);

        // 5. Build Layered Neural Objects
        this.createNeuralShell();
        this.createNeuralConnections();
        this.createInternalLattice();
        this.createOrbitalStreams();

        // 6. Event Listeners
        window.addEventListener('resize', () => this.onWindowResize());
        window.addEventListener('mousemove', (e) => this.onMouseMove(e));

        this.start();
    }

    createNeuralShell() {
        // 3,600 Particles forming a hollow neural shell (r = 4.2 to 7.2)
        const count = 3600;
        const geometry = new THREE.BufferGeometry();
        const positions = new Float32Array(count * 3);
        const colors = new Float32Array(count * 3);
        const scales = new Float32Array(count);

        const colorCyan = new THREE.Color(0x06b6d4);
        const colorBlue = new THREE.Color(0x2563eb);

        for (let i = 0; i < count; i++) {
            const u = Math.random();
            const v = Math.random();
            const theta = u * 2.0 * Math.PI;
            const phi = Math.acos(2.0 * v - 1.0);
            
            // Central hollow space (r >= 4.2)
            const r = 4.2 + Math.pow(Math.random(), 1.2) * 3.0;

            positions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
            positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
            positions[i * 3 + 2] = r * Math.cos(phi);

            const pColor = colorCyan.clone().lerp(colorBlue, Math.random());
            colors[i * 3] = pColor.r * 0.75;
            colors[i * 3 + 1] = pColor.g * 0.75;
            colors[i * 3 + 2] = pColor.b * 0.75;

            scales[i] = Math.random() * 1.2 + 0.4;
        }

        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));
        geometry.setAttribute('scale', new THREE.BufferAttribute(scales, 1));

        this.midMaterial = new THREE.ShaderMaterial({
            uniforms: {
                uTime: { value: 0 },
                uScroll: { value: 0 },
                uMode: { value: 0.0 }
            },
            vertexShader: `
                uniform float uTime;
                uniform float uScroll;
                uniform float uMode;
                attribute float scale;
                attribute vec3 color;
                varying vec3 vColor;
                
                void main() {
                    vColor = color;
                    vec3 pos = position;
                    
                    // Mode-based structural deformations
                    float wave = sin(uTime * 0.6 + pos.x * 0.7) * 0.08;
                    pos += normalize(pos) * wave;
                    
                    if (uMode > 0.5 && uMode < 1.5) {
                        // REASON mode: Align along radial steps
                        pos *= 1.0 + sin(pos.y * 3.0 + uTime) * 0.04;
                    } else if (uMode > 1.5 && uMode < 2.5) {
                        // CODE mode: Branching speed up
                        pos.x += sin(pos.z * 4.0 + uTime * 2.0) * 0.05;
                    }
                    
                    pos.z += uScroll * 3.5;
                    
                    vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
                    gl_PointSize = scale * (120.0 / -mvPosition.z);
                    gl_Position = projectionMatrix * mvPosition;
                }
            `,
            fragmentShader: `
                varying vec3 vColor;
                
                void main() {
                    float dist = length(gl_PointCoord - vec2(0.5));
                    if (dist > 0.5) discard;
                    
                    float alpha = smoothstep(0.5, 0.0, dist) * 0.28;
                    gl_FragColor = vec4(vColor, alpha);
                }
            `,
            transparent: true,
            depthWrite: false,
            blending: THREE.AdditiveBlending
        });

        this.midgroundParticles = new THREE.Points(geometry, this.midMaterial);
        this.coreGroup.add(this.midgroundParticles);
    }

    createNeuralConnections() {
        // Thin neural connection lines connecting node clusters (~300 lines)
        const lineCount = 300;
        const linePositions = new Float32Array(lineCount * 6);

        for (let i = 0; i < lineCount; i++) {
            const r1 = 4.2 + Math.random() * 2.5;
            const theta1 = Math.random() * Math.PI * 2;
            const phi1 = Math.acos(2 * Math.random() - 1);

            const x1 = r1 * Math.sin(phi1) * Math.cos(theta1);
            const y1 = r1 * Math.sin(phi1) * Math.sin(theta1);
            const z1 = r1 * Math.cos(phi1);

            // Connect to a nearby node
            const offset = (Math.random() - 0.5) * 2.0;
            const x2 = x1 + offset;
            const y2 = y1 + (Math.random() - 0.5) * 2.0;
            const z2 = z1 + (Math.random() - 0.5) * 2.0;

            linePositions[i * 6] = x1;
            linePositions[i * 6 + 1] = y1;
            linePositions[i * 6 + 2] = z1;
            linePositions[i * 6 + 3] = x2;
            linePositions[i * 6 + 4] = y2;
            linePositions[i * 6 + 5] = z2;
        }

        const lineGeo = new THREE.BufferGeometry();
        lineGeo.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));

        this.lineMaterial = new THREE.LineBasicMaterial({
            color: 0x06b6d4,
            transparent: true,
            opacity: 0.08,
            blending: THREE.AdditiveBlending
        });

        this.neuralLines = new THREE.LineSegments(lineGeo, this.lineMaterial);
        this.coreGroup.add(this.neuralLines);
    }

    createInternalLattice() {
        // Dual Icosahedron Crystalline Structure
        const innerGeo = new THREE.IcosahedronGeometry(2.8, 1);
        const innerMat = new THREE.MeshBasicMaterial({
            color: 0x06b6d4,
            wireframe: true,
            transparent: true,
            opacity: 0.05,
            blending: THREE.AdditiveBlending
        });
        this.innerLattice = new THREE.Mesh(innerGeo, innerMat);
        this.coreGroup.add(this.innerLattice);

        const outerGeo = new THREE.IcosahedronGeometry(4.8, 1);
        const outerMat = new THREE.MeshBasicMaterial({
            color: 0x2563eb,
            wireframe: true,
            transparent: true,
            opacity: 0.03,
            blending: THREE.AdditiveBlending
        });
        this.outerLattice = new THREE.Mesh(outerGeo, outerMat);
        this.coreGroup.add(this.outerLattice);
    }

    createOrbitalStreams() {
        // Orbital Torus Streams
        const ring1Geo = new THREE.TorusGeometry(6.2, 0.006, 16, 120);
        const ringMat1 = new THREE.MeshBasicMaterial({
            color: 0x06b6d4,
            transparent: true,
            opacity: 0.18,
            blending: THREE.AdditiveBlending
        });
        this.orbitalRing1 = new THREE.Mesh(ring1Geo, ringMat1);
        this.orbitalRing1.rotation.x = Math.PI / 3;
        this.coreGroup.add(this.orbitalRing1);

        const ring2Geo = new THREE.TorusGeometry(7.0, 0.005, 16, 120);
        const ringMat2 = new THREE.MeshBasicMaterial({
            color: 0x3b82f6,
            transparent: true,
            opacity: 0.14,
            blending: THREE.AdditiveBlending
        });
        this.orbitalRing2 = new THREE.Mesh(ring2Geo, ringMat2);
        this.orbitalRing2.rotation.x = -Math.PI / 4;
        this.orbitalRing2.rotation.y = Math.PI / 6;
        this.coreGroup.add(this.orbitalRing2);

        // 120 Particles flowing along the orbital streams
        const streamCount = 120;
        const streamGeo = new THREE.BufferGeometry();
        const streamPos = new Float32Array(streamCount * 3);
        this.streamAngles = new Float32Array(streamCount);
        this.streamRadii = new Float32Array(streamCount);

        for (let i = 0; i < streamCount; i++) {
            this.streamAngles[i] = Math.random() * Math.PI * 2;
            this.streamRadii[i] = (i % 2 === 0) ? 6.2 : 7.0;
            
            const a = this.streamAngles[i];
            const r = this.streamRadii[i];
            streamPos[i * 3] = r * Math.cos(a);
            streamPos[i * 3 + 1] = r * Math.sin(a) * 0.5;
            streamPos[i * 3 + 2] = r * Math.sin(a) * 0.866;
        }

        streamGeo.setAttribute('position', new THREE.BufferAttribute(streamPos, 3));
        this.orbitalParticles = new THREE.Points(streamGeo, new THREE.PointsMaterial({
            color: 0x00f2fe,
            size: 0.14,
            transparent: true,
            opacity: 0.45,
            blending: THREE.AdditiveBlending,
            depthWrite: false
        }));
        this.coreGroup.add(this.orbitalParticles);
    }

    setCapability(index) {
        this.activeCapability = index;
        if (this.midMaterial) {
            this.midMaterial.uniforms.uMode.value = parseFloat(index);
        }

        switch (index) {
            case 1: // REASON
                this.targetExpansion = 1.05;
                this.targetOrbitalSpeed = 1.2;
                this.targetLineOpacity = 0.18;
                break;
            case 2: // CODE
                this.targetExpansion = 1.12;
                this.targetOrbitalSpeed = 2.0;
                this.targetLineOpacity = 0.22;
                break;
            case 3: // SEE
                this.targetExpansion = 1.25;
                this.targetOrbitalSpeed = 1.5;
                this.targetLineOpacity = 0.15;
                break;
            case 4: // ACT
                this.targetExpansion = 1.08;
                this.targetOrbitalSpeed = 2.5;
                this.targetLineOpacity = 0.25;
                break;
            case 5: // ANALYZE
                this.targetExpansion = 0.95;
                this.targetOrbitalSpeed = 1.8;
                this.targetLineOpacity = 0.30;
                break;
            case 6: // RESEARCH
                this.targetExpansion = 1.30;
                this.targetOrbitalSpeed = 1.1;
                this.targetLineOpacity = 0.12;
                break;
            default:
                this.targetExpansion = 1.0;
                this.targetOrbitalSpeed = 1.0;
                this.targetLineOpacity = 0.08;
                break;
        }
    }

    pulseSpecialist(index) {
        this.targetLineOpacity = 0.28;
        this.targetOrbitalSpeed = 2.2;
        setTimeout(() => {
            if (this.activeCapability === 0) {
                this.targetLineOpacity = 0.08;
                this.targetOrbitalSpeed = 1.0;
            }
        }, 1200);
    }

    setSecurityMode(modeStr) {
        if (modeStr === 'safe') {
            this.targetOrbitalSpeed = 0.5;
            this.targetLineOpacity = 0.05;
        } else if (modeStr === 'ask') {
            this.targetOrbitalSpeed = 1.2;
            this.targetLineOpacity = 0.15;
        } else if (modeStr === 'full') {
            this.targetOrbitalSpeed = 2.8;
            this.targetLineOpacity = 0.32;
        }
    }

    onMouseMove(event) {
        this.targetMouse.x = (event.clientX / window.innerWidth - 0.5) * 2;
        this.targetMouse.y = -(event.clientY / window.innerHeight - 0.5) * 2;
    }

    onWindowResize() {
        if (!this.renderer || !this.camera) return;
        this.camera.aspect = window.innerWidth / window.innerHeight;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(window.innerWidth, window.innerHeight);
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
    }

    setScrollProgress(progress) {
        this.targetScroll = progress;
    }

    start() {
        if (this.isRunning) return;
        this.isRunning = true;
        this.clock.start();
        this.animate();
    }

    stop() {
        this.isRunning = false;
        if (this.animFrameId) {
            cancelAnimationFrame(this.animFrameId);
            this.animFrameId = null;
        }
    }

    animate() {
        if (!this.isRunning) return;

        this.animFrameId = requestAnimationFrame(() => this.animate());

        const elapsedTime = this.clock.getElapsedTime();

        // Smooth Interpolations
        this.currentMouse.x += (this.targetMouse.x - this.currentMouse.x) * 0.025;
        this.currentMouse.y += (this.targetMouse.y - this.currentMouse.y) * 0.025;
        this.currentScroll += (this.targetScroll - this.currentScroll) * 0.04;
        this.currentExpansion += (this.targetExpansion - this.currentExpansion) * 0.04;
        this.currentOrbitalSpeed += (this.targetOrbitalSpeed - this.currentOrbitalSpeed) * 0.04;
        this.currentLineOpacity += (this.targetLineOpacity - this.currentLineOpacity) * 0.04;

        if (this.midMaterial) {
            this.midMaterial.uniforms.uTime.value = elapsedTime;
            this.midMaterial.uniforms.uScroll.value = this.currentScroll;
        }

        if (this.lineMaterial) {
            this.lineMaterial.opacity = this.currentLineOpacity;
        }

        // Restrained Organic Rotations & Scale Expansion
        if (this.coreGroup) {
            this.coreGroup.rotation.y = elapsedTime * (0.015 * this.currentOrbitalSpeed) + this.currentMouse.x * 0.12;
            this.coreGroup.rotation.x = elapsedTime * 0.008 + this.currentMouse.y * 0.08;
            this.coreGroup.position.z = -2.0 - this.currentScroll * 2.5;
            this.coreGroup.scale.setScalar(this.currentExpansion);
        }

        if (this.innerLattice) {
            this.innerLattice.rotation.y = -elapsedTime * 0.03 * this.currentOrbitalSpeed;
            this.innerLattice.rotation.z = elapsedTime * 0.015;
        }

        if (this.outerLattice) {
            this.outerLattice.rotation.y = elapsedTime * 0.015 * this.currentOrbitalSpeed;
        }

        if (this.orbitalRing1) {
            this.orbitalRing1.rotation.z = elapsedTime * 0.03 * this.currentOrbitalSpeed;
        }

        if (this.orbitalRing2) {
            this.orbitalRing2.rotation.z = -elapsedTime * 0.025 * this.currentOrbitalSpeed;
        }

        // Flowing Orbital Stream Particles Update
        if (this.orbitalParticles) {
            const pos = this.orbitalParticles.geometry.attributes.position.array;
            const count = this.streamAngles.length;
            for (let i = 0; i < count; i++) {
                this.streamAngles[i] += 0.006 * this.currentOrbitalSpeed;
                const a = this.streamAngles[i];
                const r = this.streamRadii[i];
                pos[i * 3] = r * Math.cos(a);
                pos[i * 3 + 1] = r * Math.sin(a) * 0.5;
                pos[i * 3 + 2] = r * Math.sin(a) * 0.866;
            }
            this.orbitalParticles.geometry.attributes.position.needsUpdate = true;
        }

        // Camera Positioning & Depth
        this.camera.position.x = this.currentMouse.x * 0.3;
        this.camera.position.y = this.currentMouse.y * 0.3;
        this.camera.lookAt(0, 0, 0);

        this.renderer.render(this.scene, this.camera);
    }
}

// Global Export
window.HeroEngine = HeroEngine;
