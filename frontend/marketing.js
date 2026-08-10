/**
 * EKKI-RE-AI - Marketing Landing & View Controller (Final Art Direction Pass)
 * Interactive WebGL State Synchronization (Capabilities, Specialists, Security Modes)
 * Seamless view switching & complete VRAM pausing on Console launch.
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize Three.js Hero Engine if canvas exists
    if (typeof HeroEngine !== 'undefined' && document.getElementById('bg-canvas')) {
        window.heroEngine = new HeroEngine();
    }

    const marketingView = document.getElementById('marketing-view');
    const consoleView = document.getElementById('console-view');

    // 2. View Transition Functions
    function showConsoleView() {
        if (!consoleView) return;

        if (typeof gsap !== 'undefined' && marketingView) {
            gsap.to(marketingView, {
                opacity: 0,
                duration: 0.35,
                ease: 'power2.inOut',
                onComplete: () => {
                    marketingView.style.display = 'none';
                    document.body.classList.add('console-mode');
                    consoleView.classList.remove('hidden-view');
                    consoleView.style.display = 'flex';
                    gsap.fromTo(consoleView, { opacity: 0 }, { opacity: 1, duration: 0.35 });
                    
                    // STOP 3D WebGL render loop completely to preserve GPU VRAM for Ollama LLM
                    if (window.heroEngine) {
                        window.heroEngine.stop();
                    }
                    window.scrollTo(0, 0);
                }
            });
        } else {
            if (marketingView) marketingView.style.display = 'none';
            document.body.classList.add('console-mode');
            consoleView.classList.remove('hidden-view');
            consoleView.style.display = 'flex';
            if (window.heroEngine) {
                window.heroEngine.stop();
            }
            window.scrollTo(0, 0);
        }
    }

    function showMarketingView() {
        if (!marketingView || !consoleView) return;

        if (typeof gsap !== 'undefined') {
            gsap.to(consoleView, {
                opacity: 0,
                duration: 0.35,
                ease: 'power2.inOut',
                onComplete: () => {
                    consoleView.style.display = 'none';
                    consoleView.classList.add('hidden-view');
                    document.body.classList.remove('console-mode');
                    marketingView.style.display = 'block';
                    gsap.fromTo(marketingView, { opacity: 0 }, { opacity: 1, duration: 0.35 });

                    // RESUME 3D WebGL render loop when returning to landing page
                    if (window.heroEngine) {
                        window.heroEngine.start();
                    }
                    window.scrollTo(0, 0);
                }
            });
        } else {
            consoleView.style.display = 'none';
            consoleView.classList.add('hidden-view');
            document.body.classList.remove('console-mode');
            marketingView.style.display = 'block';
            if (window.heroEngine) {
                window.heroEngine.start();
            }
            window.scrollTo(0, 0);
        }
    }

    // Export navigation methods globally
    window.showConsoleView = showConsoleView;
    window.showMarketingView = showMarketingView;

    // 3. Attach Event Listeners to CTA buttons
    const tryButtons = [
        document.getElementById('btn-try-ekki'),
        document.getElementById('nav-try-ekki-btn'),
        document.getElementById('hero-console-launch-btn')
    ];

    tryButtons.forEach(btn => {
        if (btn) {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                showConsoleView();
            });
        }
    });

    const homeBrandBtns = [
        document.getElementById('marketing-brand-logo'),
        document.getElementById('console-brand-home-btn')
    ];

    homeBrandBtns.forEach(btn => {
        if (btn) {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                showMarketingView();
            });
        }
    });

    // Smooth Scroll links
    document.querySelectorAll('.marketing-nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            const targetId = link.getAttribute('href');
            if (targetId && targetId.startsWith('#')) {
                e.preventDefault();
                const targetEl = document.querySelector(targetId);
                if (targetEl) {
                    targetEl.scrollIntoView({ behavior: 'smooth' });
                }
            }
        });
    });

    // 4. Interactive Capability Transformations
    document.querySelectorAll('.spatial-item').forEach((item, index) => {
        item.addEventListener('mouseenter', () => {
            if (window.heroEngine) {
                window.heroEngine.setCapability(index + 1);
            }
        });
        item.addEventListener('mouseleave', () => {
            if (window.heroEngine) {
                window.heroEngine.setCapability(0);
            }
        });
    });

    // 5. Interactive Specialist Network Pulsing
    document.querySelectorAll('.constellation-row').forEach((row, index) => {
        row.addEventListener('mouseenter', () => {
            if (window.heroEngine) {
                window.heroEngine.pulseSpecialist(index);
            }
        });
    });

    // 6. Security Mode Timeline Interaction
    document.querySelectorAll('.timeline-mode').forEach(modeEl => {
        modeEl.addEventListener('mouseenter', () => {
            const modeTag = modeEl.querySelector('.mode-tag');
            if (modeTag && window.heroEngine) {
                if (modeTag.classList.contains('safe')) {
                    window.heroEngine.setSecurityMode('safe');
                } else if (modeTag.classList.contains('ask')) {
                    window.heroEngine.setSecurityMode('ask');
                } else if (modeTag.classList.contains('full')) {
                    window.heroEngine.setSecurityMode('full');
                }
            }
        });
        modeEl.addEventListener('mouseleave', () => {
            if (window.heroEngine) {
                window.heroEngine.setSecurityMode('ask');
            }
        });
    });

    // 7. GSAP ScrollTrigger Animations
    if (typeof gsap !== 'undefined' && typeof ScrollTrigger !== 'undefined') {
        gsap.registerPlugin(ScrollTrigger);

        // Scroll Progress Sync with HeroEngine
        ScrollTrigger.create({
            trigger: "#marketing-view",
            start: "top top",
            end: "bottom bottom",
            onUpdate: (self) => {
                if (window.heroEngine) {
                    window.heroEngine.setScrollProgress(self.progress);
                }
            }
        });

        // Hero Entrance Sequence
        const heroTl = gsap.timeline();
        heroTl.from(".hero-label-tag", { opacity: 0, y: 15, duration: 0.8, ease: "power2.out" })
              .from(".hero-title", { opacity: 0, y: 25, duration: 1.0, ease: "power2.out" }, "-=0.5")
              .from(".hero-subtitle", { opacity: 0, y: 15, duration: 0.8, ease: "power2.out" }, "-=0.6")
              .from(".hero-actions", { opacity: 0, y: 15, duration: 0.8, ease: "power2.out" }, "-=0.6");

        // Spatial List Items Reveal
        gsap.utils.toArray(".spatial-item").forEach((item, i) => {
            gsap.from(item, {
                scrollTrigger: {
                    trigger: item,
                    start: "top 85%",
                    toggleActions: "play none none reverse"
                },
                opacity: 0,
                y: 25,
                duration: 0.7,
                delay: (i % 3) * 0.1,
                ease: "power2.out"
            });
        });

        // Constellation Rows Reveal
        gsap.utils.toArray(".constellation-row").forEach((row, i) => {
            gsap.from(row, {
                scrollTrigger: {
                    trigger: row,
                    start: "top 85%",
                    toggleActions: "play none none reverse"
                },
                opacity: 0,
                y: 20,
                duration: 0.6,
                delay: (i % 4) * 0.08,
                ease: "power2.out"
            });
        });

        // Future Climax Reveal
        gsap.from(".climax-headline", {
            scrollTrigger: {
                trigger: "#climax",
                start: "top 75%",
                toggleActions: "play none none reverse"
            },
            opacity: 0,
            y: 35,
            duration: 1.1,
            ease: "power2.out"
        });
    }
});
