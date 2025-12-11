import {
    u as e,
    ir as t,
    M as o,
    is as a,
    Q as i,
    it as n,
    iu as c,
    iv as s,
    iw as u,
    am as l,
    aK as r,
    p as d,
    ez as p,
    n as y,
    H as v,
    ix as m,
    iy as f,
    b as M,
    V as h,
    iz as g,
    iA as I,
    iB as T,
    iC as w,
    iD as b,
    b5 as N,
    iE as P,
    iF as C
} from "./utils-lib.js?v=1763689792";
import {
    j as L,
    r as _,
    t as E,
    o as D,
    g as O
} from "./base-lib.js?v=1763689792";
import {
    p as A,
    b as x
} from "./validator.js?v=1763689792";
const S = L("PRODUCT-PAYMENT-STORE", () => {
    const L = _({}),
        S = _(),
        B = _(!1),
        {
            payment: V,
            authTypeTitle: R,
            isUpdatePayment: q,
            isRefreshSoftList: U,
            setAuthState: F,
            authExpirationTime: j,
            forceLtd: H,
            aliyunEcsLtd: W,
            getUnbindNumber: k
        } = e(),
        {
            authType: Y,
            voucherOpenTime: G,
            newUserVoucherOpenTime: z,
            bindUser: J,
            isGetCoupon: K
        } = E(V.value),
        Q = _(!1),
        Z = _(),
        $ = _(!1),
        X = _(!1),
        ee = D({}),
        te = _(!0),
        oe = _(!1),
        ae = D({
            cycleMode: {
                activeCycleInfo: {
                    cycle: 12
                },
                list: []
            },
            numsMode: {
                list: [],
                activeNumsInfo: {
                    count: 1,
                    price: 0,
                    discount: 0
                }
            },
            couponMode: {
                status: !1,
                activeCouponId: "",
                activeCouponInfo: {},
                discountsTitle: "",
                disabled: !1,
                count: 0,
                list: [],
                endTimeNum: 0
            },
            couponInfo: {
                [t.pro]: [],
                [t.ltd]: [],
                [t.dev]: []
            },
            enterpriseMode: {
                status: !1,
                isHidden: !1
            },
            devCycleInfo: {
                isGetOperated: !1,
                data: {}
            },
            voucherMode: {
                loading: !1,
                isExist: !1,
                proTypeList: {},
                typeActive: 0,
                typeList: {},
                list: [],
                active: 0,
                activeInfo: {
                    pid: 0,
                    code: ""
                }
            },
            payMode: {
                activePayType: "wechat",
                activeBuyInfo: {
                    price: 0,
                    count: 0,
                    cycle: 0,
                    originalPrice: 0,
                    discount: 0
                },
                activeBalanceInfo: {},
                balance: 0,
                activePayCode: {
                    apliy: "",
                    wechat: ""
                },
                qrcode: {
                    value: "",
                    size: 110
                },
                payTips: {
                    status: !1,
                    name: "",
                    day: 0
                },
                isLastBuyRepeat: !1,
                lastPayTime: 0,
                createOrderTime: []
            }
        }),
        ie = D({
            right: !0,
            left: !1
        }),
        ne = _(!1),
        ce = D({
            d: "00",
            h: "00",
            m: "00",
            s: "00"
        });
    let se = null,
        ue = null;
    const le = D({
            status: !0,
            title: "正在获取产品信息，请稍侯..."
        }),
        re = D({
            status: !0,
            title: "正在生成支付订单，请稍侯..."
        }),
        de = D({
            status: !1,
            title: ""
        }),
        pe = _(!1),
        ye = _(!1),
        ve = _(),
        me = _(0),
        fe = O(() => "".concat("alipay" === (null == ae ? void 0 : ae.payMode.activePayType) ? "ali" : "wechat", "-pay.svg")),
        Me = () => {
            var e;
            const t = document.getElementById("list-box"),
                o = 172 * ae.cycleMode.list.length;
            if (null === t) return;
            const a = t.clientWidth;
            if (o < a) return;
            const i = document.getElementById("list"),
                n = Math.abs(parseInt(null == (e = window.getComputedStyle(i, null)) ? void 0 : e.left, 10));
            n + a - 360 < a ? (i.style.left = "0px", ie.right = !0, ie.left = !1) : i.style.left = "-".concat(n - 360, "px")
        },
        he = async e => {
            Me(), le.status = !0, ae.enterpriseMode.status = !1;
            const {
                ltd: o
            } = t;
            switch ("string" == typeof e && (e = ee.typeList.find(t => t.type === e)), ee.activeTypeInfo = e, ae.cycleMode.list = [], ae.numsMode.activeNumsInfo.count = 1, ee.unbindAuthor.status = !1, ee.unbindAuthor.count = 0, $e(), e.type) {
                case "coupon":
                    le.title = "正在获取产品抵扣券，请稍侯...", await Ze({
                        pid: e.pid
                    }), le.status = !1, ae.voucherMode.proTypeList[t.coupon] && Ke({
                        pid: t.coupon,
                        list: ae.voucherMode.proTypeList[t.coupon].list
                    }), ae.voucherMode.proTypeList[t.pro] && Ke({
                        pid: t.pro,
                        list: ae.voucherMode.proTypeList[t.pro].list
                    }), ae.voucherMode.proTypeList[o] && Ke({
                        pid: o,
                        list: ae.voucherMode.proTypeList[o].list
                    });
                    break;
                case "plugin":
                case "ltd":
                case "pro":
                case "dev":
                    le.title = "正在获取产品信息，请稍侯...", J.value ? await Je(e.pid) : (lt(e.type), dt(), Re()), le.status = !1, ge(ae.cycleMode.list[0])
            }
        }, ge = async (e, t) => {
            var o;
            rt("cycle", e) && (ae.numsMode.list = e.nums, ae.cycleMode.activeCycleInfo = e, ae.enterpriseMode.isHidden = !("ltd" === (null == ee ? void 0 : ee.activeTypeInfo.type) && 12 === e.cycle), void 0 === t && !ae.enterpriseMode.isHidden && ae.enterpriseMode.status && (ae.enterpriseMode.status = !1), $e(), (null == (o = e.nums) ? void 0 : o.length) && await Ie(e.nums[0]))
        }, Ie = async e => {
            var t, o;
            if (!rt("nums", e)) return;
            ae.numsMode.activeNumsInfo = e;
            const a = [],
                {
                    list: i
                } = ae.couponMode;
            if (("pro" === (null == ee ? void 0 : ee.activeTypeInfo.type) || "ltd" === (null == ee ? void 0 : ee.activeTypeInfo.type)) && i.length > 0 && (i.forEach(t => {
                    Number(t.val1) <= e.price && a.push(t)
                }), a.length)) return ae.couponMode.status = !0, a.sort((e, t) => Number(t.val2) - Number(e.val2)), Te(null == (t = a[0].id) ? void 0 : t.toString()), !1;
            if (!ne.value && ae.couponMode.count > 0) {
                const t = i.filter(t => Number(t.val1) <= e.price)[0];
                t || (ae.couponMode.status = !1), ne.value = !0, ae.couponMode.activeCouponId = null == (o = null == t ? void 0 : t.id) ? void 0 : o.toString(), ae.couponMode.endTimeNum = Math.floor((null == t ? void 0 : t.endtime) - Math.floor((new Date).getTime() / 1e3))
            }
            be()
        }, Te = async e => {
            if (!e) return ae.couponMode.status = !1, o.error("请选择优惠券");
            const t = ae.couponMode.list.find(t => t.id === Number(e)) || {};
            if (t.val1 && Number(t.val1) <= ae.numsMode.activeNumsInfo.price) {
                ae.couponMode.status = !0, ae.couponMode.activeCouponId = e.toString();
                const t = ae.couponMode.list.find(t => t.id === Number(e));
                void 0 !== t && (ae.couponMode.activeCouponInfo = t, ae.couponMode.endTimeNum = Math.floor(t.endtime - Math.floor((new Date).getTime() / 1e3)), t.name.indexOf("0.99") > -1 ? ae.couponMode.discountsTitle = t.name : ae.couponMode.discountsTitle = "已使用优惠券，立减".concat(t.val2, "元"))
            }
            be()
        }, we = _(!1), be = async (e = {
            pid: Number(ae.numsMode.activeNumsInfo.pid),
            cycle: Number(ae.cycleMode.activeCycleInfo.cycle),
            source: Number(Z.value),
            num: Number(ae.numsMode.activeNumsInfo.count),
            coupon: ae.couponMode.status && ae.couponMode.activeCouponId || "",
            get_ali_msg: 0,
            regain: 0
        }, s = !0) => {
            var u;
            if (!W.value) try {
                const l = (new Date).getTime() / 1e3;
                ae.payMode.createOrderTime.push(l), s && (re.status = !0);
                const {
                    data: r
                } = await a(e), {
                    activeTypeInfo: d
                } = ee, {
                    pid: p
                } = d, {
                    status: y
                } = ae.enterpriseMode;
                if (p === t.ltd && (y && Number(e.pid) !== t.dev || !y && Number(e.pid) !== t.ltd) || p !== t.ltd && Number(e.pid) !== p || Number(ae.numsMode.activeNumsInfo.count) !== e.num || e.cycle !== Number(ae.cycleMode.activeCycleInfo.cycle)) return;
                if ("string" == typeof r.data && "inherit_order" === r.data) return o.msg({
                    message: r.msg,
                    type: "warning"
                }), await at(), be();
                if ("string" == typeof r.msg && -1 !== r.msg.indexOf("接口请求失败")) return void o.msg({
                    customClass: "panel-cloud-error",
                    dangerouslyUseHTMLString: !0,
                    message: r.msg,
                    type: "error",
                    duration: 0,
                    showClose: !0
                });
                if (!r.status && 1e3 === (null == (u = r.data) ? void 0 : u.code)) return de.status = !0, re.status = !1, void(de.title = r.data.msg);
                const {
                    ali_msg: v,
                    msg: m,
                    extra: f,
                    data: M,
                    is_coupon: h,
                    status_code: g
                } = r, {
                    cash_fee: I,
                    uid: T
                } = M;
                if (ae.payMode.activeBuyInfo = Ge(I, r), 120 === g && f) {
                    if (ae.payMode.payTips.name = f.name, "pro" === ee.activeTypeInfo.type && "永久授权" === j.value) return ee.unbindAuthor.status = !0, ee.unbindAuthor.count = null == f ? void 0 : f.rest_unbind_count, re.status = !1, nt.value = {
                        type: null == ee ? void 0 : ee.activeTypeInfo.type,
                        typeName: R.value,
                        extra: f
                    }, !1;
                    ae.payMode.payTips.status = !0;
                    const e = (new Date(1e3 * f.end_time).getTime() - (new Date).getTime()) / 864e5;
                    ae.payMode.payTips.day = Math.ceil(e)
                } else ae.payMode.payTips.status = !1;
                if (h && h.length > 0 && G.value < (new Date).getTime() / 1e3 && 100 !== G.value) pe.value = !0, Ve({
                    isCoupon: h
                });
                else if (!ye.value && ae.couponMode.list.length > 0 && !$.value && !pe.value) {
                    ye.value = !0;
                    const {
                        val1: e,
                        val2: t,
                        id: o,
                        pid: a
                    } = ae.couponMode.list[0];
                    Te(o)
                }
                if (M.returnTime = l, ae.payMode.activeBalanceInfo = M, ae.payMode.lastPayTime <= 0) {
                    if (!M.pid) return void o.error("请求失败");
                    i({
                        request: n({
                            pid: M.pid
                        }),
                        data: {
                            res: [Number, "buyVerify"]
                        },
                        success: e => {
                            e && (ae.payMode.lastPayTime = e.buyVerify, Ce())
                        }
                    })
                } else Ce();
                const {
                    credits: w
                } = await i({
                    request: c({
                        uid: T
                    }),
                    data: {
                        res: [Number, "credits"]
                    }
                });
                ae.payMode.balance = w / 100;
                const {
                    createOrderTime: b
                } = ae.payMode;
                if (b[b.length - 1] !== M.returnTime) return !1;
                re.status = !1, ae.payMode.balance >= ae.payMode.activeBuyInfo.price ? ae.payMode.activePayType = "balance" : ae.payMode.activeBuyInfo.price >= 6e3 ? (we.value = !0, ae.payMode.activePayType = "wechat" === ae.payMode.activePayType ? "alipay" : ae.payMode.activePayType) : ae.payMode.balance < ae.payMode.activeBuyInfo.price && (ae.payMode.activeBuyInfo.price < 6e3 ? ae.payMode.activePayType = "wechat" : ae.payMode.activePayType = "alipay"), we.value && ae.payMode.activeBuyInfo.price < 6e3 && (ae.payMode.activePayType = "wechat", we.value = !1), ae.payMode.activePayCode.apliy = v, ae.payMode.activePayCode.wechat = m, ae.payMode.qrcode.value = "wechat" === ae.payMode.activePayType ? m : v, "ltd" === (null == ee ? void 0 : ee.activeTypeInfo.type) && _e(ae.numsMode.activeNumsInfo.count), se && clearTimeout(se), "coupon" !== (null == ee ? void 0 : ee.activeTypeInfo.type) && setTimeout(() => {
                    te.value = !0, Fe((new Date).getTime() / 1e3)
                }, 5e3), (() => {
                    const e = {
                        cycleMode: ae.cycleMode,
                        numsMode: ae.numsMode,
                        payMode: ae.payMode,
                        typeTab: null == ee ? void 0 : ee.activeTypeInfo.type,
                        enterpriseMode: ae.enterpriseMode,
                        couponMode: ae.couponMode
                    };
                    sessionStorage.setItem("PAY-VIEW-INFO", JSON.stringify(e))
                })()
            } catch (l) {}
        }, Ne = _({}), Pe = _(), Ce = () => {
            (new Date).getTime() / 1e3 - ae.payMode.lastPayTime < 1800 ? ae.payMode.isLastBuyRepeat = !0 : ae.payMode.isLastBuyRepeat = !1
        }, Le = _(0), _e = async e => {
            let t = [];
            if (ae.devCycleInfo.isGetOperated && ae.devCycleInfo.data.nums.length) t = ae.devCycleInfo.data.nums;
            else {
                const {
                    data: e
                } = await s({
                    pid: 100000068
                });
                t = e[12].nums, ae.devCycleInfo.isGetOperated = !0, ae.devCycleInfo.data = e[12]
            }
            const o = t.find(t => t.count === e);
            o && (Le.value = o.price)
        }, Ee = _(""), De = _(!1), Oe = _(Math.floor(Date.now() / 1e3)), Ae = _([]), xe = _(!1), Se = _(), Be = _(), Ve = async e => {
            W.value || (Ae.value = e.isCoupon, xe.value = e.isHome || !1, Se.value = y({
                area: 40,
                component: () => v(() => import("./index338.js?v=1763689792"), __vite__mapDeps([]),
                    import.meta.url),
                customClass: "voucherFetchView",
                compData: e,
                onCancel: () => {
                    De.value && window.location.reload()
                }
            }))
        }, Re = async () => {
            W.value || V.value.bindUser || (Be.value = y({
                area: 40,
                component: () => v(() => import("./index438.js?v=1763689792"), __vite__mapDeps([]),
                    import.meta.url),
                customClass: "voucherFetchView"
            }))
        }, qe = async (e, t) => {
            await Ue(), t !== (null == ee ? void 0 : ee.activeTypeInfo.type) && await he(t), await Te(e)
        }, Ue = async () => {
            W.value || (ae.couponInfo[t.pro] = [], ae.couponInfo[t.ltd] = [], ae.couponInfo[t.dev] = [], J.value && await i({
                request: m(),
                data: {
                    res: [Array, "data"]
                },
                success: e => {
                    const t = (new Date).getTime() / 1e3;
                    e.data.forEach(e => {
                        var o;
                        const a = Math.floor((e.endtime - Math.floor(t)) / 3600);
                        let i = 0;
                        a > 24 ? i = Math.floor(a / 24) : a > 0 && (i = 1), e.newName = "".concat(e.name, "( ").concat(i, "天后过期)"), null == (o = ae.couponInfo[e.product_id]) || o.push(e)
                    }), $e()
                }
            }))
        }, Fe = async e => {
            try {
                if (!B.value) return;
                e && sessionStorage.setItem("PAY-VIEW-INFO-TIME", "".concat(e));
                const t = sessionStorage.getItem("PAY-VIEW-INFO-TIME");
                if (t) {
                    if (parseInt("".concat((new Date).getTime() / 1e3 - Number(t)), 10) > 600 && B.value) return te.value = !1, sessionStorage.removeItem("PAY-VIEW-INFO-TIME"), d({
                        title: "支付超时",
                        icon: "warning",
                        content: "由于您长时间未操作，支付超时，请刷新网页重新购买！",
                        onConfirm: () => {
                            Xe(), window.location.reload()
                        },
                        onCancel: () => {
                            Xe(), window.location.reload()
                        }
                    });
                    B.value || sessionStorage.removeItem("PAY-VIEW-INFO-TIME")
                }
                if (se && clearTimeout(se), "coupon" === (null == ee ? void 0 : ee.activeTypeInfo.type) || ee.unbindAuthor.status) return;
                if ("balance" === ae.payMode.activePayType) return void(se = setTimeout(() => {
                    Fe()
                }, 4e3));
                const o = (new Date).getTime() / 1e3,
                    {
                        status: a,
                        data: n
                    } = await i({
                        request: f({
                            wxoid: ae.payMode.activeBalanceInfo.wxoid,
                            py_type: "alipay" === ae.payMode.activePayType ? "ali" : ""
                        }),
                        data: {
                            status: [Boolean, "status"],
                            data: [Object, "data"]
                        }
                    });
                if (n && ["WAIT_BUYER_PAY", "TRADE_CLOSED"].includes(n.status) && (oe.value = !0), a) Ye();
                else {
                    const e = (new Date).getTime() / 1e3;
                    ue = setTimeout(Fe, e - o < 1 ? 4e3 : 3e3)
                }
            } catch (t) {
                r(t)
            }
        }, je = () => {
            (window.location.pathname.includes("/waf") || H.value) && window.location.reload()
        }, He = async () => {
            -1 !== window.location.pathname.indexOf("/soft/plugin") && (q.value = !0, U.value = !0)
        }, We = _({}), ke = async () => {
            const {
                data: e
            } = await b({
                force: 1
            }), {
                ltd: t,
                pro: o
            } = new N(e, {
                ltd: Number,
                pro: Number
            }).exportData();
            return F([0, o, t]), {
                ltd: t,
                pro: o
            }
        }, Ye = async () => {
            var e, t, o;
            try {
                await He(), Xe();
                const a = await ke();
                if ("plugin" === (null == (e = null == ee ? void 0 : ee.activeTypeInfo) ? void 0 : e.type)) return M().success("".concat(ee.activeTypeInfo.title, "支付成功"));
                const i = "dev" === (null == (t = null == ee ? void 0 : ee.activeTypeInfo) ? void 0 : t.type) ? "ltd" : (null == (o = null == ee ? void 0 : ee.activeTypeInfo) ? void 0 : o.type) || "";
                Object.assign(We.value, {
                    type: ee.activeTypeInfo.type,
                    typeTipsList: ee.activeTypeInfo.tipsList,
                    cycle: ae.payMode.activeBuyInfo.cycle,
                    count: ae.payMode.activeBuyInfo.count,
                    lastTime: h(a[i]),
                    title: ee.activeTypeInfo.title
                }), y({
                    area: 68,
                    component: () => v(() => import("./index439.js?v=1763689792"), __vite__mapDeps([]),
                        import.meta.url)
                }), je()
            } catch (a) {
                r(a)
            }
        }, Ge = (e, t) => {
            const {
                cycleMode: o,
                numsMode: a,
                couponMode: i
            } = ae, {
                activeCycleInfo: n
            } = o, c = n.originalPrice, {
                activeNumsInfo: s
            } = a, {
                activeCouponInfo: u,
                status: l
            } = i;
            let r = e / 100,
                d = n.title || "",
                p = s.count || 0;
            const y = c * p;
            return l && (u.name.includes("0.99") ? (r = y - u.val1, d = "".concat(u.experimental_interval, "天"), p = 1) : r = t.price), {
                price: r,
                count: p,
                cycle: d,
                originalPrice: y,
                discount: u
            }
        }, ze = _(!1), Je = async e => {
            try {
                ze.value = !0;
                const {
                    data: o
                } = await s({
                    pid: e
                });
                Number(o.pid) === t.dev && (delete o[1], delete o[6], delete o[36], ae.devCycleInfo.isGetOperated = !0, ae.devCycleInfo.data = o[12]);
                const a = [];
                for (const e in o)
                    if (Object.prototype.hasOwnProperty.call(o, e)) {
                        const {
                            price: t,
                            tip: i,
                            sprice: n,
                            nums: c,
                            sort: s
                        } = o[e];
                        if (!isNaN(Number(e))) {
                            const o = Number(e) % 12 == 0 ? "".concat(Number(e) / 12, "年") : "".concat(Number(e), "个月");
                            a.push({
                                cycle: Number(e),
                                price: t,
                                recommend: i,
                                originalPrice: n,
                                nums: c,
                                sort: s,
                                title: o,
                                everyDay: (t / Number(e) / 30).toFixed(2)
                            })
                        }
                    } a.sort((e, t) => e.sort - t.sort), ae.cycleMode.list = a
            } catch (o) {
                r(o)
            } finally {
                ze.value = !1
            }
        }, Ke = e => {
            const {
                list: t,
                pid: a
            } = e;
            return ae.voucherMode.list = t, ae.voucherMode.typeActive = a, t.length ? Qe(t[0]) : o.warn("暂无可用优惠券")
        }, Qe = e => {
            const {
                id: t,
                product_id: o,
                code: a
            } = e;
            ae.voucherMode.active = t, ae.voucherMode.activeInfo = {
                pid: o,
                code: a
            }
        }, Ze = async e => {
            try {
                ae.voucherMode.loading = !0, ae.voucherMode.list = [], ae.voucherMode.typeList = {}, ae.voucherMode.proTypeList = {};
                const {
                    data: t
                } = await g(e);
                ae.voucherMode.isExist = !(0 === t.length), t.forEach(e => {
                    const {
                        product_id: t,
                        name: o
                    } = e;
                    ae.voucherMode.typeList.hasOwnProperty(t) ? ae.voucherMode.typeList[t].list.push(e) : ae.voucherMode.typeList[t] = {
                        name: o,
                        pid: t,
                        list: [e]
                    }
                });
                ["100000011", "100000032"].reverse().forEach(e => {
                    if (ae.voucherMode.typeList[e]) {
                        const t = ae.voucherMode.typeList[e];
                        ae.voucherMode.proTypeList[e] = t, delete ae.voucherMode.typeList[e]
                    }
                })
            } catch (t) {
                r(t)
            } finally {
                ae.voucherMode.loading = !1
            }
        }, $e = () => {
            var e;
            const {
                type: o,
                pid: a
            } = ee.activeTypeInfo;
            if (["plugin", "coupon"].includes(o)) ae.couponMode.count = 0, ae.couponMode.list = [];
            else {
                let i = a;
                ae.enterpriseMode.status && "ltd" === o && (i = t.dev), ae.couponMode.count = (null == (e = ae.couponInfo[i]) ? void 0 : e.length) || 0, ae.couponMode.list = ae.couponInfo[i]
            }
            ae.couponMode = {
                status: !1,
                activeCouponId: "",
                activeCouponInfo: {},
                discountsTitle: "",
                count: ae.couponMode.count,
                list: ae.couponMode.list,
                disabled: !ae.couponMode.count,
                endTimeNum: 0
            }, ae.couponMode.count <= 0 && (ae.couponMode.disabled = !0, ae.couponMode.status = !1)
        }, Xe = async () => {
            window.onbeforeunload = () => {}, yt(), S.value("close")
        }, et = _(), tt = _(!1), ot = _([{
            type: "wechat",
            title: "微信扫码支付"
        }, {
            type: "alipay",
            title: "支付宝扫码支付"
        }, {
            type: "balance",
            title: "余额支付"
        }, {
            type: "accounts",
            title: "对公转账"
        }]), at = async () => {
            var e;
            try {
                await ke() && (o.request({
                    msg: "刷新成功",
                    status: !0
                }), (null == (e = null == ee ? void 0 : ee.activeTypeInfo) ? void 0 : e.type) && he(ee.activeTypeInfo.type))
            } catch (t) {
                r(t)
            }
        }, it = _(!1), nt = _({}), ct = _(!1), st = _(), ut = e => {
            nt.value = e, st.value = y({
                area: [32, 29],
                component: () => v(() => import("./index441.js?v=1763689792"), __vite__mapDeps([]),
                    import.meta.url)
            })
        }, lt = e => {
            ae.cycleMode.list = "dev" === e ? [{
                cycle: 12,
                price: 5999,
                recommend: !1,
                originalPrice: 12e3,
                nums: [{
                    count: 1,
                    price: -1,
                    discount: 0
                }, {
                    count: 3,
                    price: -1,
                    discount: 0
                }, {
                    count: 5,
                    price: -1,
                    discount: 0
                }, {
                    count: 10,
                    price: -1,
                    discount: 0
                }, {
                    count: 20,
                    price: -1,
                    discount: 0
                }, {
                    count: 50,
                    price: -1,
                    discount: 0
                }, {
                    count: 100,
                    price: -1,
                    discount: 0
                }],
                sort: 1,
                title: "1年",
                everyDay: "16.66"
            }] : [{
                cycle: 12,
                price: 1399,
                recommend: !1,
                originalPrice: 3588,
                nums: [{
                    count: 1,
                    price: -1,
                    discount: 0
                }, {
                    count: 3,
                    price: -1,
                    discount: 0
                }, {
                    count: 5,
                    price: -1,
                    discount: 0
                }, {
                    count: 10,
                    price: -1,
                    discount: 0
                }, {
                    count: 20,
                    price: -1,
                    discount: 0
                }, {
                    count: 50,
                    price: -1,
                    discount: 0
                }, {
                    count: 100,
                    price: -1,
                    discount: 0
                }],
                sort: 1,
                title: "1年",
                everyDay: "3.89"
            }, {
                cycle: 36,
                price: 2999,
                recommend: !1,
                originalPrice: 10764,
                nums: [{
                    count: 1,
                    price: -1,
                    discount: 0
                }, {
                    count: 3,
                    price: -1,
                    discount: 0
                }, {
                    count: 5,
                    price: -1,
                    discount: 0
                }, {
                    count: 10,
                    price: -1,
                    discount: 0
                }, {
                    count: 20,
                    price: -1,
                    discount: 0
                }, {
                    count: 50,
                    price: -1,
                    discount: 0
                }, {
                    count: 100,
                    price: -1,
                    discount: 0
                }],
                sort: 2,
                title: "3年",
                everyDay: "2.78"
            }, {
                cycle: 6,
                price: 999,
                recommend: !1,
                originalPrice: 1794,
                nums: [{
                    count: 1,
                    price: -1,
                    discount: 0
                }, {
                    count: 3,
                    price: -1,
                    discount: 0
                }, {
                    count: 5,
                    price: -1,
                    discount: 0
                }, {
                    count: 10,
                    price: -1,
                    discount: 0
                }, {
                    count: 20,
                    price: -1,
                    discount: 0
                }, {
                    count: 50,
                    price: -1,
                    discount: 0
                }, {
                    count: 100,
                    price: -1,
                    discount: 0
                }],
                sort: 3,
                title: "6个月",
                everyDay: "5.55"
            }, {
                cycle: 1,
                price: 599,
                recommend: !1,
                originalPrice: 599,
                nums: [{
                    count: 1,
                    price: -1,
                    discount: 0
                }, {
                    count: 3,
                    price: -1,
                    discount: 0
                }, {
                    count: 5,
                    price: -1,
                    discount: 0
                }, {
                    count: 10,
                    price: -1,
                    discount: 0
                }, {
                    count: 20,
                    price: -1,
                    discount: 0
                }, {
                    count: 50,
                    price: -1,
                    discount: 0
                }, {
                    count: 100,
                    price: -1,
                    discount: 0
                }],
                sort: 4,
                title: "1个月",
                everyDay: "19.97"
            }]
        }, rt = (e, t) => !(!J.value && ("nums" === e && 1 !== t.count || "cycle" === e && 12 !== t.cycle)) || (x(), !1), dt = () => {
            let e = Number(sessionStorage.getItem("PAYMENT-NEW-COUPON-TIME"));
            (!e || e < (new Date).getTime()) && (e = (new Date).getTime() + 6e5, sessionStorage.setItem("PAYMENT-NEW-COUPON-TIME", e.toString())), me.value = e
        }, pt = _(0), yt = () => {
            we.value = !1, B.value = !1, oe.value = !1, ue && clearTimeout(ue), se && clearTimeout(se), ve.value && clearInterval(ve.value)
        };
    return {
        voucherFetchInstance: Se,
        openNewUserVoucherFetchViewDialog: Re,
        compData: L,
        isRemarksLoading: tt,
        productPriceLoading: ze,
        isPlugin: Q,
        productInfo: ee,
        product: ae,
        enterprise: Le,
        tabLoading: le,
        iSwitch: ie,
        countDown: ce,
        switchLeft: Me,
        switchRight: () => {
            const e = document.getElementById("list-box"),
                t = 172 * ae.cycleMode.list.length,
                o = e.clientWidth;
            if (t < o) return;
            const a = document.getElementById("list"),
                i = Math.abs(parseInt(window.getComputedStyle(a, null).left, 10));
            i + o + 360 > t ? (a.style.left = "-".concat(t - o, "px"), ie.right = !1, ie.left = !0) : a.style.left = "-".concat(i + 360, "px")
        },
        changeTypeTabEvent: he,
        changeCycleTabEvent: ge,
        changeNumsTabEvent: Ie,
        enterpriseEvent: e => {
            ae.enterpriseMode.status = Boolean(e), e ? ge({
                cycle: 12,
                price: ae.devCycleInfo.data.price,
                recommend: !1,
                originalPrice: ae.devCycleInfo.data.sprice,
                nums: ae.devCycleInfo.data.nums,
                sort: 0,
                title: "1年",
                everyDay: (ae.devCycleInfo.data.price / 12 / 30).toFixed(2)
            }, "dev") : ge(ae.cycleMode.list[0])
        },
        changeCouponBoxEvent: e => {
            const {
                status: t,
                count: a,
                activeCouponId: i
            } = ae.couponMode;
            if (0 === a) return ae.couponMode.status = !1, o.warn("暂无可用优惠券");
            if (ae.couponMode.status = void 0 !== e ? Boolean(e) : !t, "" !== i && ae.couponMode.status) Te(i);
            else if ("" === i && ae.couponMode.status) return o.request({
                msg: "请选择优惠券",
                status: !1
            }), ae.couponMode.status = !1, !1;
            be()
        },
        changeCouponEvent: Te,
        openPrivilegeContrast: () => {
            et.value = y({
                area: [97, 76],
                component: () => v(() => import("./index440.js?v=1763689792"), __vite__mapDeps([]),
                    import.meta.url)
            })
        },
        newUserVoucherFetchInstance: Be,
        newUserVoucherEndTime: me,
        scanned: oe,
        errorMask: de,
        bindUser: J,
        paymentLoading: re,
        payList: ot,
        changePayTypeEvent: async e => {
            switch (oe.value = !1, e.type) {
                case "wechat":
                    if (ae && (null == ae ? void 0 : ae.payMode.activeBuyInfo.price) >= 6e3) return o.warn("刷新支付金额已超过微信单笔支付额度，请选择其他支付方式"), !1;
                    ae.payMode.qrcode.value = ae.payMode.activePayCode.wechat;
                    break;
                case "alipay":
                    "" === ae.payMode.activePayCode.apliy || e.isRegain ? (await be({
                        pid: Number(ae.numsMode.activeNumsInfo.pid),
                        cycle: Number(ae.cycleMode.activeCycleInfo.cycle),
                        source: Number(Z.value),
                        num: Number(ae.numsMode.activeNumsInfo.count),
                        coupon: ae.couponMode.status && ae.couponMode.activeCouponId || "",
                        get_ali_msg: 1,
                        regain: e.isRegain ? 1 : 0
                    }, !0), ae.payMode.qrcode.value = ae.payMode.activePayCode.apliy, oe.value = !1) : ae.payMode.qrcode.value = ae.payMode.activePayCode.apliy
            }
            ae.payMode.activePayType = e.type
        },
        paySuccessData: We,
        openBuySuccessView: Ye,
        changeBalanceBuyEvent: async () => {
            var e, t, a, n, c, s, u, l;
            await i({
                loading: "正在支付中...",
                request: I({
                    num: Number(null == (t = null == (e = null == ae ? void 0 : ae.numsMode) ? void 0 : e.activeNumsInfo) ? void 0 : t.count),
                    cycle: Number(null == (n = null == (a = null == ae ? void 0 : ae.cycleMode) ? void 0 : a.activeCycleInfo) ? void 0 : n.cycle),
                    uid: Number(null == (s = null == (c = null == ae ? void 0 : ae.payMode) ? void 0 : c.activeBalanceInfo) ? void 0 : s.uid),
                    pid: Number(null == (l = null == (u = null == ae ? void 0 : ae.payMode) ? void 0 : u.activeBalanceInfo) ? void 0 : l.pid),
                    coupon: ae.couponMode.status && ae.couponMode.activeCouponId || ""
                }),
                data: {
                    res: String,
                    success: Boolean
                },
                success: e => {
                    o.request({
                        msg: e.res,
                        status: e.success
                    }), e.success && Ye()
                }
            })
        },
        changeRefreshAuthor: at,
        couponItem: Ae,
        closeAfterReload: De,
        timeClose: Ee,
        siteList: [{
            label: "今日内不再提醒",
            value: "today"
        }, {
            label: "近7天内不再提醒",
            value: "week"
        }, {
            label: "永久不再提醒",
            value: "forver"
        }],
        timeNow: Oe,
        addZero: e => e < 10 ? "0".concat(e) : "".concat(e),
        claimCouponEvent: async e => {
            try {
                const {
                    data: t
                } = await u();
                if (K.value = !0, l(null == t ? void 0 : t.status) && 0 === (null == t ? void 0 : t.status)) return o.request({
                    msg: t.msg,
                    status: !1
                }), void(De.value = !0);
                const a = {
                        100000011: "pro",
                        100000032: "ltd",
                        100000068: "dev"
                    } [t.data[0].pid],
                    {
                        id: i
                    } = t.data[0];
                o.request({
                    msg: t.msg,
                    status: !0
                });
                const n = await Se.value;
                if (null == n || n.unmount(), e && "function" == typeof e && e(), xe.value) return await A({
                    disablePro: "pro" !== a,
                    sourceId: 176,
                    isHomeBubble: {
                        id: i,
                        pro: a
                    }
                }), !1;
                await qe(i, a)
            } catch (t) {
                r(t)
            }
        },
        changeCloseTimeEvent: async (e, t = !0) => {
            let a = 0,
                i = "";
            switch (Ee.value = e, Ee.value) {
                case "today":
                    a = new Date((new Date).toLocaleDateString()).getTime() + 864e5 - 1, i = "今日内不再通知";
                    break;
                case "week":
                    a = new Date((new Date).toLocaleDateString()).getTime() + 6048e5 - 1, i = "近7天内不再通知";
                    break;
                case "forver":
                    a = -100, i = "永久不再通知"
            }
            if (a = Math.floor(a > 0 ? a / 1e3 : a), t && await d({
                    title: "提示",
                    content: "".concat(i, ",是否确认?")
                }), xe.value) G.value = a, sessionStorage.setItem("voucherOpenTime", G.value.toString());
            else try {
                const e = await p({
                    limit_time: a
                });
                t && o.request(e)
            } catch (c) {
                r(c)
            }
            const n = await Se.value;
            null == n || n.unmount(), K.value = !0
        },
        couponCompData: Ne,
        changeVoucher: async () => {
            Te(Ne.value.id);
            const e = await Pe.value;
            null == e || e.unmount()
        },
        activePayIcon: fe,
        voucherLoading: it,
        getVoucherCycleDescribe: (e, t) => "month" === t ? e % 12 ? "".concat(e, "个月") : "".concat(e / 12, "年") : "".concat(e + ("year" === t ? "年" : "天")),
        useChangeVoucher: async () => {
            if (it.value = !0, "" === (null == ae ? void 0 : ae.voucherMode.activeInfo.code)) return o.warn("请选择抵扣券");
            const {
                status: e,
                extra: t,
                statusCode: a,
                msg: n
            } = await i({
                loading: "正在使用抵扣券，请稍侯...",
                request: T({
                    pid: Number(null == ae ? void 0 : ae.voucherMode.activeInfo.pid),
                    code: (null == ae ? void 0 : ae.voucherMode.activeInfo.code) || ""
                }),
                data: {
                    extra: [Object, "extra"],
                    status: Boolean,
                    status_code: [Number, "statusCode"],
                    msg: String
                }
            });
            it.value = !1, e ? (await ke(), o.request({
                msg: n,
                status: e
            }), He(), Xe(), je()) : 120 !== a || e ? o.request({
                msg: n,
                status: e
            }) : (it.value = !1, ut({
                type: null == ee ? void 0 : ee.activeTypeInfo.type,
                typeName: R.value,
                extra: t
            }))
        },
        changeVoucherEvent: Qe,
        changeVoucherTypeEvent: Ke,
        refreshSoftEvent: He,
        unbindBuyAuthorDialog: ut,
        authTypeTitle: R,
        authExpirationTime: j,
        getUnbindCount: async () => {
            const e = await k();
            pt.value = e
        },
        unBindAuthor: () => {
            ut({
                type: null == ee ? void 0 : ee.activeTypeInfo.type,
                typeName: R.value,
                extra: {
                    rest_unbind_count: pt.value
                }
            })
        },
        isDisabledAuth: ct,
        authType: Y,
        bindAuthData: nt,
        changeUnbindAuthor: async (e = !1) => {
            if (nt.value.extra.rest_unbind_count > 0) try {
                await d({
                    title: "提示",
                    content: "解绑当前【".concat(R.value, "授权】，继续操作！")
                }), ct.value = !0;
                const {
                    data: a
                } = await w();
                if (o.request({
                        msg: a.res,
                        status: a.success
                    }), a.success) {
                    await ke(), e ? setTimeout(() => {
                        he(ee.activeTypeInfo.type)
                    }, 500) : await Ze({
                        pid: t.coupon
                    }), He();
                    const o = await st.value;
                    null == o || o.unmount()
                }
            } catch (a) {} finally {
                ct.value = !1
            } else window.open("https://www.bt.cn/admin/profe_ee", "_blank", "noopener,noreferrer")
        },
        privilegeList: ["多对一技术支持", "全年5次安全排查", "5分钟极速响应", "30+款付费插件", "20+企业版专享功能", "1000条免费短信（年付）", "2张SSL商用证书（年付）", "一对一服务（年付）", "WAF防火墙", "更换授权IP", "客服优先响应", "15+款付费插件", "15天无理由退款"],
        proPrivilegeList: [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1],
        ltdPrivilegeList: [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        plusPrivilegeList: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        go2tab: async e => {
            he(e);
            const t = await et.value;
            null == t || t.unmount()
        },
        emits: S,
        onCancel: async () => W.value ? (ke(), Xe(), !1) : J.value ? (await d({
            title: "温馨提示",
            content: '支付过程中，请勿关闭该页面，以免出现支付异常！<br><a\n\t\t\t\tclass="bt-link text-small"\n\t\t\t\thref="https://www.bt.cn/new/wechat_customer"\n\t\t\t\ttarget="_blank"\n\t\t\t\trel="noreferrer noopener"\n\t\t\t\t>支付遇到问题？联系客服</a\n\t\t\t>',
            isHtml: !0,
            width: "40rem"
        }), Xe(), !1) : (Xe(), !1),
        init: async e => {
            e && (L.value = e), B.value = !0, (() => {
                const {
                    pluginInfo: e,
                    disablePro: o
                } = L.value;
                Q.value = !!e, Z.value = L.value.sourceId, X.value = o, $.value = L.value.isHomeBubble, Object.assign(ee, {
                    typeList: [{
                        type: "plugin",
                        title: Q.value ? e.title : "插件",
                        describe: Q.value ? 8 === e.type ? "【专业版】已包含此插件" : "【企业版】已包含此插件" : "",
                        pid: Q.value ? e.pid : 0,
                        isHidden: !Q.value,
                        tipsTitle: "插件说明",
                        tipsList: []
                    }, {
                        type: "pro",
                        title: "".concat(C, "专业版"),
                        describe: "适用于个人用户、个人项目",
                        pid: t.pro,
                        isHidden: o,
                        tipsTitle: "专业版特权",
                        tipsList: []
                    }, {
                        type: "ltd",
                        title: "".concat(C, "企业版"),
                        describe: "适用于官网，电商、教育、医疗等用户",
                        pid: t.ltd,
                        recommend: !0,
                        tipsTitle: "企业版特权",
                        tipsList: []
                    }, {
                        type: "dev",
                        title: "企业运维托管",
                        describe: "适用于无专业技术、需技术服务的企业",
                        pid: t.dev,
                        tipsTitle: "企业运维托管特权",
                        isHidden: Q.value,
                        tipsList: ["网站性能优化", "网站安全扫描", "网站攻击防护", "服务器运维托管", "企业版所有特权", "文件防篡改配置", "文件代码同步部署", "系统文件垃圾清理", "数据库数据同步部署", "50x/40x网站报错处理", "CPU内存占用过高处理"]
                    }, {
                        type: "coupon",
                        title: "抵扣券",
                        describe: "抵扣券授权",
                        pid: t.coupon,
                        tipsTitle: "抵扣券来源",
                        tipsList: ["官网后台购买", "活动页购买", "推广赠送", "更换绑定IP"]
                    }],
                    activityList: "",
                    activeTypeInfo: {
                        type: "pro",
                        describe: "",
                        title: "",
                        pid: 0,
                        recommend: !1,
                        tipsTitle: "",
                        tipsList: []
                    },
                    unbindAuthor: {
                        status: !1,
                        count: 0
                    }
                })
            })(), (async () => {
                let e = sessionStorage.getItem("PAY-VIEW-INFO-REMARKS");
                e || await i({
                    loading: tt,
                    request: P(),
                    data: {
                        pro_list: [Array, "pro"],
                        list: [Array, "ltd"],
                        vip_pro_list: [Array, "vip_pro_list"],
                        activity_list: [Array, "activityList"]
                    },
                    success: t => {
                        e = JSON.stringify(t), sessionStorage.setItem("PAY-VIEW-INFO-REMARKS", e)
                    }
                });
                const t = JSON.parse(e);
                tt.value = !1;
                const {
                    pro: o,
                    ltd: a,
                    vip_pro_list: n,
                    activityList: c
                } = t;
                ee.typeList[1].tipsList = o, ee.typeList[2].tipsList = a, ee.typeList[3].tipsList = n, (new DOMParser).parseFromString(c, "text/xml"), ee.activityList = c || "", ee.activeTypeInfo = ee.typeList.find(e => e.type === ee.activeTypeInfo.type), Ue()
            })(), tt.value = !0;
            let o = (() => {
                if (W.value) return "dev";
                let e = "free" === Y.value ? "ltd" : Y.value;
                return X.value || "ltd" === e || (e = "pro"), e
            })();
            var a;
            const n = ((e, t) => null == t ? void 0 : t.some(t => t.type === e))(o, null == (a = null == ee ? void 0 : ee.typeList) ? void 0 : a.filter(e => !0 !== (null == e ? void 0 : e.isHidden)));
            n || (o = "ltd"), await he(o), (async () => {
                if ($.value && Object.keys($.value).length > 0 && "object" == typeof $.value) {
                    const {
                        id: e,
                        pro: t
                    } = $.value;
                    await qe(e, t)
                }
            })(), V.value.bindUser && (window.onbeforeunload = () => "是否要离开")
        },
        $reset: yt
    }
});
export {
    S as P
};

function __vite__mapDeps(indexes) {
    if (!__vite__mapDeps.viteFileDeps) {
        __vite__mapDeps.viteFileDeps = []
    }
    return indexes.map((i) => __vite__mapDeps.viteFileDeps[i])
}