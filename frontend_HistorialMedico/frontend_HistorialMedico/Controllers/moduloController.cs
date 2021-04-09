using frontend_HistorialMedico.Filters;
using HistorialMedicoUtil;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace frontend_SoftColegio.Controllers
{
    public class moduloController : Controller
    {
        [SecuritySession]
        public ActionResult Index()
        {
            ViewBag.GrolUsuario = UtlAuditoria.ObtenerTipoUsuario();
            return View();
        }
    }
}