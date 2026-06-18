(function() {
    // Generate or retrieve session ID
    function getSessionId() {
        let sid = sessionStorage.getItem("dg_session_id");
        if (!sid) {
            sid = 'dg_sess_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
            sessionStorage.setItem("dg_session_id", sid);
        }
        return sid;
    }

    // Try to auto-detect logged-in user on Forem/DEV.to
    function getLoggedInUsername() {
        if (window.currentUser && window.currentUser.username) {
            return window.currentUser.username;
        }
        const usernameMeta = document.querySelector('meta[name="user-username"]');
        if (usernameMeta) {
            return usernameMeta.getAttribute("content");
        }
        const userProfileLink = document.querySelector('a[href^="/"][class*="user"], a[href^="/"][class*="profile"]');
        if (userProfileLink) {
            const href = userProfileLink.getAttribute("href");
            if (href && href !== "/" && !href.startsWith("/settings")) {
                return href.replace("/", "");
            }
        }
        return null;
    }

    // Canvas fingerprinting
    function getCanvasHash() {
        try {
            const canvas = document.createElement("canvas");
            const ctx = canvas.getContext("2d");
            if (!ctx) return "unsupported";
            canvas.width = 200;
            canvas.height = 50;
            ctx.textBaseline = "top";
            ctx.font = "14px 'Arial'";
            ctx.textBaseline = "alphabetic";
            ctx.fillStyle = "#f60";
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = "#069";
            ctx.fillText("DevGuard, anti-bot? ⚡", 2, 15);
            ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
            ctx.fillText("DevGuard, anti-bot? ⚡", 4, 17);
            const dataURL = canvas.toDataURL();
            let hash = 0;
            for (let i = 0; i < dataURL.length; i++) {
                hash = (hash << 5) - hash + dataURL.charCodeAt(i);
                hash |= 0;
            }
            return hash.toString(16);
        } catch (e) {
            return "error_" + e.message;
        }
    }

    // WebGL info
    function getWebGLInfo() {
        try {
            const canvas = document.createElement("canvas");
            const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
            if (!gl) return { vendor: "unsupported", renderer: "unsupported" };
            const dbgRenderInfo = gl.getExtension("WEBGL_debug_renderer_info");
            if (dbgRenderInfo) {
                return {
                    vendor: gl.getParameter(dbgRenderInfo.UNMASKED_VENDOR_WEBGL),
                    renderer: gl.getParameter(dbgRenderInfo.UNMASKED_RENDERER_WEBGL)
                };
            }
            return { vendor: gl.getParameter(gl.VENDOR), renderer: gl.getParameter(gl.RENDERER) };
        } catch (e) {
            return { vendor: "error", renderer: "error" };
        }
    }

    // --- TELEMETRY COLLECTION STATE ---
    const telemetry = {
        mouse: {
            total_moves: 0,
            points: [],            // sample of [{x, y, t}]
            speeds: [],            // list of speeds px/ms
            angles: [],            // list of movement directions (radians)
            robotic_lines: 0       // counts consecutive straight lines
        },
        keyboard: {
            total_keys: 0,
            key_down_times: {},    // temp map {key: time}
            dwell_times: [],       // list of press durations (ms)
            flight_times: [],      // list of release-to-press times
            last_keyup_time: 0,
            paste_count: 0
        },
        scroll: {
            scroll_count: 0,
            last_scroll_time: 0,
            scroll_deltas: []
        }
    };

    // Listeners for Mouse Telemetry
    document.addEventListener("mousemove", (e) => {
        telemetry.mouse.total_moves++;
        const now = performance.now();
        const newPoint = { x: e.clientX, y: e.clientY, t: now };
        
        // Limit sample size stored to prevent memory growth
        if (telemetry.mouse.points.length < 100) {
            const points = telemetry.mouse.points;
            if (points.length > 0) {
                const prev = points[points.length - 1];
                const dx = newPoint.x - prev.x;
                const dy = newPoint.y - prev.y;
                const dt = newPoint.t - prev.t;
                
                if (dt > 0) {
                    // Speed calculation
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    const speed = dist / dt;
                    telemetry.mouse.speeds.push(speed);
                    
                    // Angle calculation
                    const angle = Math.atan2(dy, dx);
                    telemetry.mouse.angles.push(angle);
                    
                    // Straight line analysis (bots moving in perfect linear steps)
                    if (telemetry.mouse.angles.length > 1) {
                        const prevAngle = telemetry.mouse.angles[telemetry.mouse.angles.length - 2];
                        if (Math.abs(angle - prevAngle) < 0.0001) {
                            telemetry.mouse.robotic_lines++;
                        }
                    }
                }
            }
            telemetry.mouse.points.push(newPoint);
        }
    });

    // Listeners for Keyboard Telemetry
    document.addEventListener("keydown", (e) => {
        const now = performance.now();
        telemetry.keyboard.total_keys++;
        
        if (!telemetry.keyboard.key_down_times[e.key]) {
            telemetry.keyboard.key_down_times[e.key] = now;
        }
        
        if (telemetry.keyboard.last_keyup_time > 0 && telemetry.keyboard.flight_times.length < 50) {
            const flight = now - telemetry.keyboard.last_keyup_time;
            telemetry.keyboard.flight_times.push(flight);
        }
    });

    document.addEventListener("keyup", (e) => {
        const now = performance.now();
        const start = telemetry.keyboard.key_down_times[e.key];
        
        if (start && telemetry.keyboard.dwell_times.length < 50) {
            const dwell = now - start;
            telemetry.keyboard.dwell_times.push(dwell);
            delete telemetry.keyboard.key_down_times[e.key];
        }
        
        telemetry.keyboard.last_keyup_time = now;
    });

    document.addEventListener("paste", () => {
        telemetry.keyboard.paste_count++;
    });

    // Listeners for Scroll Telemetry
    document.addEventListener("scroll", () => {
        telemetry.scroll.scroll_count++;
        const now = performance.now();
        
        if (telemetry.scroll.last_scroll_time > 0 && telemetry.scroll.scroll_deltas.length < 50) {
            const delta = now - telemetry.scroll.last_scroll_time;
            telemetry.scroll.scroll_deltas.push(delta);
        }
        telemetry.scroll.last_scroll_time = now;
    });

    // --- SUBMISSION LOGIC ---
    let hasSent = false;
    
    async function collectAndSend() {
        if (hasSent) return;
        hasSent = true;

        const glInfo = getWebGLInfo();
        
        // Calculate telemetry summary statistics on the client side
        const mouseSpeeds = telemetry.mouse.speeds;
        const mouseMeanSpeed = mouseSpeeds.length > 0 ? (mouseSpeeds.reduce((a, b) => a + b, 0) / mouseSpeeds.length) : 0;
        const mouseSpeedVar = mouseSpeeds.length > 0 ? (mouseSpeeds.reduce((a, b) => a + Math.pow(b - mouseMeanSpeed, 2), 0) / mouseSpeeds.length) : 0;

        const dwellTimes = telemetry.keyboard.dwell_times;
        const dwellMean = dwellTimes.length > 0 ? (dwellTimes.reduce((a, b) => a + b, 0) / dwellTimes.length) : 0;
        const dwellVar = dwellTimes.length > 0 ? (dwellTimes.reduce((a, b) => a + Math.pow(b - dwellMean, 2), 0) / dwellTimes.length) : 0;

        const payload = {
            session_id: getSessionId(),
            username: getLoggedInUsername(),
            webdriver: navigator.webdriver || false,
            cdp_artifacts: !!(
                window.cdc_adoQy255tRx5d7DKCXNJemc_Array ||
                window.cdc_adoQy255tRx5d7DKCXNJemc_Promise ||
                window.cdc_adoQy255tRx5d7DKCXNJemc_Symbol ||
                window.$cdc_asdjflasg_ ||
                window.__webdriver_evaluate ||
                window.__selenium_evaluate ||
                window.__puppeteer ||
                window.__playwright
            ),
            plugins_len: navigator.plugins ? navigator.plugins.length : 0,
            languages: navigator.languages ? navigator.languages.join(",") : navigator.language,
            canvas_hash: getCanvasHash(),
            webgl_vendor: glInfo.vendor,
            webgl_renderer: glInfo.renderer,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            screen_res: `${window.screen.width}x${window.screen.height}`,
            platform: navigator.platform || "unknown",
            notification_permission: window.Notification ? Notification.permission : "unsupported",
            permission_state: "unsupported",
            
            // --- INJECT TELEMETRY METRICS ---
            telemetry: {
                mouse_moves: telemetry.mouse.total_moves,
                mouse_mean_speed: mouseMeanSpeed,
                mouse_speed_variance: mouseSpeedVar,
                mouse_robotic_lines: telemetry.mouse.robotic_lines,
                
                key_presses: telemetry.keyboard.total_keys,
                key_mean_dwell: dwellMean,
                key_dwell_variance: dwellVar,
                key_paste_count: telemetry.keyboard.paste_count,
                
                scroll_events: telemetry.scroll.scroll_count,
                scroll_intervals_variance: telemetry.scroll.scroll_deltas.length > 0 ? 
                    (telemetry.scroll.scroll_deltas.reduce((a, b) => a + Math.pow(b - (telemetry.scroll.scroll_deltas.reduce((x, y) => x + y, 0)/telemetry.scroll.scroll_deltas.length), 2), 0) / telemetry.scroll.scroll_deltas.length) : 0
            }
        };

        if (navigator.permissions && window.Notification) {
            try {
                const permissionStatus = await navigator.permissions.query({ name: "notifications" });
                payload.permission_state = permissionStatus.state;
            } catch (e) {}
        }

        const backendHost = window.DEVGUARD_HOST || "";
        const endpoint = `${backendHost}/api/realtime/fingerprint`;

        try {
            await fetch(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
        } catch (err) {
            console.warn("DevGuard failed to log fingerprint telemetry:", err);
        }
    }

    // Trigger transmission after 5 seconds of load (to collect telemetry)
    const sendTimeout = setTimeout(collectAndSend, 5000);

    // Or trigger immediately if the user focuses on any inputs or textareas (anticipating submission)
    document.addEventListener("focusin", (e) => {
        if (e.target && (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA")) {
            clearTimeout(sendTimeout);
            // Small delay to ensure we capture some initial interaction data
            setTimeout(collectAndSend, 500);
        }
    });

    // Or trigger when page is unloading
    window.addEventListener("beforeunload", collectAndSend);
})();
