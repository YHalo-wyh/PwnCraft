/**
 * PwnCraft heap physics — a small deterministic 2D rigid-body engine (v0.29).
 *
 * The heap canvas is no longer a static diagram: every chunk card is a
 * semi-anchored rigid body, every bin/pointer relation is a spring, and
 * overlap groups collide.  The allocator truth (who owns which bytes, who
 * points where) still comes from the Python engine per step; this world only
 * makes that truth *move*: cards pop in on alloc, snap on bin transitions,
 * and settle under spring forces each animation frame.
 *
 * Units are abstract canvas units; integration is semi-implicit Euler with
 * fixed substeps so stepping the timeline is reproducible.
 */
(() => {
  'use strict';

  class PhysicsWorld {
    constructor() {
      this.bodies = [];
      this.springs = [];
      this.gravity = 0;          // heap layout is top-down memory, keep 0
      this.damping = 0.86;
      this.springK = 0.012;      // base stiffness
      this.springDamp = 0.34;    // per-spring velocity damping
      this.iterations = 3;       // collision solver iterations per substep
      this.time = 0;
    }

    addBody(body) {
      const defaults = {
        x: 0, y: 0, w: 60, h: 40,
        vx: 0, vy: 0,
        mass: 1,
        pinned: false,           // immovable (e.g. bin head rails)
        anchorX: null, anchorY: null, // weak home spring target (null = free)
        anchorK: 0.02,
        born: 0,                 // world time when spawned (pop-in scale)
        data: null,
      };
      const merged = { ...defaults, ...body };
      merged.anchorX = merged.anchorX === null ? merged.x : merged.anchorX;
      merged.anchorY = merged.anchorY === null ? merged.y : merged.anchorY;
      this.bodies.push(merged);
      return merged;
    }

    removeBody(body) {
      this.bodies = this.bodies.filter((item) => item !== body);
      this.springs = this.springs.filter(
        (spring) => spring.a !== body && spring.b !== body,
      );
    }

    clear() {
      this.bodies = [];
      this.springs = [];
      this.time = 0;
    }

    addSpring(spec) {
      const defaults = {
        a: null, b: null,
        rest: 80,
        k: this.springK,
        damp: this.springDamp,
        kind: 'link',          // link | anchor | drag
        visible: true,
        data: null,
      };
      const spring = { ...defaults, ...spec };
      this.springs.push(spring);
      return spring;
    }

    removeSpringsWhere(predicate) {
      this.springs = this.springs.filter((spring) => !predicate(spring));
    }

    impulse(body, ix, iy) {
      if (!body || body.pinned) return;
      body.vx += ix;
      body.vy += iy;
    }

    /** One fixed substep.  dt is abstract; forces are tuned for dt=1. */
    step(dt = 1) {
      this.time += dt;
      for (let sub = 0; sub < 2; sub += 1) {
        this._applyForces(dt / 2);
        this._integrate(dt / 2);
        this._solveCollisions();
        this._solveBounds();
      }
    }

    _applyForces(dt) {
      for (const spring of this.springs) {
        const a = spring.a;
        const b = spring.b;
        if (!a || !b) continue;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.max(1, Math.hypot(dx, dy));
        const diff = (dist - spring.rest) / dist;
        const fx = dx * diff * spring.k * dt;
        const fy = dy * diff * spring.k * dt;
        // relative velocity damping along the spring axis
        const rvx = b.vx - a.vx;
        const rvy = b.vy - a.vy;
        const dvx = rvx * spring.damp * dt * 0.5;
        const dvy = rvy * spring.damp * dt * 0.5;
        if (!a.pinned) {
          a.vx += fx - dvx * 0.5;
          a.vy += fy - dvy * 0.5;
        }
        if (!b.pinned) {
          b.vx -= fx + dvx * 0.5;
          b.vy -= fy + dvy * 0.5;
        }
      }
      for (const body of this.bodies) {
        // weak home spring keeps cards readable while still physically alive
        if (body.anchorX !== null && body.anchorY !== null && !body.pinned && !body.dragging) {
          const dx = body.anchorX - body.x;
          const dy = body.anchorY - body.y;
          body.vx += dx * body.anchorK * dt;
          body.vy += dy * body.anchorK * dt;
          body.vx *= 0.9;
          body.vy *= 0.9;
        }
        body.vy += this.gravity * dt;
        const d = Math.pow(this.damping, dt);
        body.vx *= d;
        body.vy *= d;
      }
    }

    _integrate(dt) {
      for (const body of this.bodies) {
        if (body.pinned || body.dragging) {
          body.vx = 0;
          body.vy = 0;
          continue;
        }
        body.x += body.vx * dt;
        body.y += body.vy * dt;
      }
    }

    _solveCollisions() {
      for (let iter = 0; iter < this.iterations; iter += 1) {
        const bodies = this.bodies;
        for (let i = 0; i < bodies.length; i += 1) {
          for (let j = i + 1; j < bodies.length; j += 1) {
            const a = bodies[i];
            const b = bodies[j];
            if (a.pinned && b.pinned) continue;
            if (a.noCollide || b.noCollide) continue;
            const overlapX = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
            const overlapY = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
            if (overlapX <= 0 || overlapY <= 0) continue;
            // resolve along the smaller axis like a position-based impulse
            const total = a.mass + b.mass;
            if (overlapX < overlapY) {
              const push = overlapX / 2;
              const sign = a.x <= b.x ? -1 : 1;
              this._separate(a, b, sign * push * 2 / total * a.mass * 2, 0);
            } else {
              const push = overlapY / 2;
              const sign = a.y <= b.y ? -1 : 1;
              this._separate(a, b, 0, sign * push * 2 / total * a.mass * 2);
            }
          }
        }
      }
    }

    _separate(a, b, ix, iy) {
      const total = (a.mass + b.mass) || 1;
      const aShare = a.pinned ? 0 : (b.mass / total);
      const bShare = b.pinned ? 0 : (a.mass / total);
      if (!a.pinned) { a.x += ix * aShare; a.y += iy * aShare; }
      if (!b.pinned) { b.x -= ix * bShare; b.y -= iy * bShare; }
    }

    _solveBounds() {
      for (const body of this.bodies) {
        if (body.pinned) continue;
        if (body.minX !== undefined && body.x < body.minX) {
          body.x = body.minX;
          body.vx = Math.abs(body.vx) * 0.3;
        }
        if (body.minY !== undefined && body.y < body.minY) {
          body.y = body.minY;
          body.vy = Math.abs(body.vy) * 0.3;
        }
        if (body.maxY !== undefined && body.y > body.maxY) {
          body.y = body.maxY;
          body.vy = -Math.abs(body.vy) * 0.3;
        }
      }
    }

    /** Total kinetic energy — the canvas uses this to detect "settled". */
    energy() {
      let sum = 0;
      for (const body of this.bodies) {
        sum += body.vx * body.vx + body.vy * body.vy;
      }
      return sum;
    }
  }

  window.PwnPhysics = { PhysicsWorld };
})();
