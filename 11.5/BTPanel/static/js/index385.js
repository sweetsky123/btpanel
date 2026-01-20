import{a5 as c,D as _,_ as i}from"./utils-lib.js?v=1768643427";import{c as u,r as d,w as l,a8 as m,x as p,y as f,e as v,z as b}from"./base-lib.js?v=1768643427";import{u as x,N as T}from"./useStore13.js?v=1768643427";import"./__commonjsHelpers__.js?v=1768643427";const h={class:"set-node-tabs"},E=u({__name:"index",setup(N){const{settingTabActive:e,isJump:s,setNodeInfo:o}=x(),{resetTab:r}=T(),t=d(e.value||"ssh"),{BtTabs:n}=c({type:"left-bg-card",value:t,options:[{label:"SSH",name:"ssh",lazy:!0,render:()=>_(()=>import("./index386.js?v=1768643427"),__vite__mapDeps([]),import.meta.url)}]});return l(()=>s.value,a=>{a&&(t.value=e.value,r())}),m(()=>{o.value={}}),(a,S)=>(p(),f("div",h,[v(b(n))]))}}),I=i(E,[["__scopeId","data-v-f48b8aed"]]);export{I as default};
function __vite__mapDeps(indexes) {
  if (!__vite__mapDeps.viteFileDeps) {
    __vite__mapDeps.viteFileDeps = []
  }
  return indexes.map((i) => __vite__mapDeps.viteFileDeps[i])
}
